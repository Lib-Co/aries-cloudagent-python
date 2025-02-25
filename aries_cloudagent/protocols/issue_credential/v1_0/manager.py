"""Classes to manage credentials."""

import asyncio
import json
import logging

from typing import Mapping, Tuple

from ....cache.base import BaseCache
from ....core.error import BaseError
from ....core.profile import Profile
from ....indy.holder import IndyHolder, IndyHolderError
from ....indy.issuer import IndyIssuer, IndyIssuerRevocationRegistryFullError
from ....ledger.base import BaseLedger
from ....messaging.credential_definitions.util import (
    CRED_DEF_TAGS,
    CRED_DEF_SENT_RECORD_TYPE,
)
from ....messaging.responder import BaseResponder
from ....revocation.indy import IndyRevocation
from ....revocation.models.revocation_registry import RevocationRegistry
from ....revocation.models.issuer_rev_reg_record import IssuerRevRegRecord
from ....revocation.util import notify_revocation_reg_event
from ....storage.base import BaseStorage
from ....storage.error import StorageError, StorageNotFoundError

from .messages.credential_ack import CredentialAck
from .messages.credential_issue import CredentialIssue
from .messages.credential_offer import CredentialOffer
from .messages.credential_problem_report import (
    CredentialProblemReport,
    ProblemReportReason,
)
from .messages.credential_proposal import CredentialProposal
from .messages.credential_request import CredentialRequest
from .messages.inner.credential_preview import CredentialPreview
from .models.credential_exchange import V10CredentialExchange

LOGGER = logging.getLogger(__name__)


class CredentialManagerError(BaseError):
    """Credential error."""


class CredentialManager:
    """Class for managing credentials."""

    def __init__(self, profile: Profile):
        """
        Initialize a CredentialManager.

        Args:
            profile: The profile instance for this credential manager
        """
        self._profile = profile

    @property
    def profile(self) -> Profile:
        """
        Accessor for the current profile instance.

        Returns:
            The profile instance for this credential manager

        """
        return self._profile

    async def _match_sent_cred_def_id(self, tag_query: Mapping[str, str]) -> str:
        """Return most recent matching id of cred def that agent sent to ledger."""

        async with self._profile.session() as session:
            storage = session.inject(BaseStorage)
            found = await storage.find_all_records(
                type_filter=CRED_DEF_SENT_RECORD_TYPE, tag_query=tag_query
            )
        if not found:
            raise CredentialManagerError(
                f"Issuer has no operable cred def for proposal spec {tag_query}"
            )
        return max(found, key=lambda r: int(r.tags["epoch"])).tags["cred_def_id"]

    async def prepare_send(
        self,
        connection_id: str,
        credential_proposal: CredentialProposal,
        auto_remove: bool = None,
        comment: str = None,
    ) -> Tuple[V10CredentialExchange, CredentialOffer]:
        """
        Set up a new credential exchange for an automated send.

        Args:
            connection_id: Connection to create offer for
            credential_proposal: The credential proposal with preview
            auto_remove: Flag to automatically remove the record on completion

        Returns:
            A tuple of the new credential exchange record and credential offer message

        """
        if auto_remove is None:
            auto_remove = not self._profile.settings.get("preserve_exchange_records")
        credential_exchange = V10CredentialExchange(
            connection_id=connection_id,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            credential_proposal_dict=credential_proposal,
            auto_issue=True,
            auto_remove=auto_remove,
            trace=(credential_proposal._trace is not None),
        )
        (credential_exchange, credential_offer) = await self.create_offer(
            cred_ex_record=credential_exchange,
            counter_proposal=None,
            comment=comment,
        )
        return (credential_exchange, credential_offer)

    async def create_proposal(
        self,
        connection_id: str,
        *,
        auto_offer: bool = None,
        auto_remove: bool = None,
        comment: str = None,
        credential_preview: CredentialPreview = None,
        schema_id: str = None,
        schema_issuer_did: str = None,
        schema_name: str = None,
        schema_version: str = None,
        cred_def_id: str = None,
        issuer_did: str = None,
        trace: bool = False,
    ) -> V10CredentialExchange:
        """
        Create a credential proposal.

        Args:
            connection_id: Connection to create proposal for
            auto_offer: Should this proposal request automatically be handled to
                offer a credential
            auto_remove: Should the record be automatically removed on completion
            comment: Optional human-readable comment to include in proposal
            credential_preview: The credential preview to use to create
                the credential proposal
            schema_id: Schema id for credential proposal
            schema_issuer_did: Schema issuer DID for credential proposal
            schema_name: Schema name for credential proposal
            schema_version: Schema version for credential proposal
            cred_def_id: Credential definition id for credential proposal
            issuer_did: Issuer DID for credential proposal

        Returns:
            Resulting credential exchange record including credential proposal

        """
        credential_proposal_message = CredentialProposal(
            comment=comment,
            credential_proposal=credential_preview,
            schema_id=schema_id,
            schema_issuer_did=schema_issuer_did,
            schema_name=schema_name,
            schema_version=schema_version,
            cred_def_id=cred_def_id,
            issuer_did=issuer_did,
        )
        credential_proposal_message.assign_trace_decorator(
            self._profile.settings, trace
        )

        if auto_remove is None:
            auto_remove = not self._profile.settings.get("preserve_exchange_records")
        cred_ex_record = V10CredentialExchange(
            connection_id=connection_id,
            thread_id=credential_proposal_message._thread_id,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_PROPOSAL_SENT,
            credential_proposal_dict=credential_proposal_message,
            auto_offer=auto_offer,
            auto_remove=auto_remove,
            trace=trace,
        )
        async with self._profile.session() as session:
            await cred_ex_record.save(session, reason="create credential proposal")
        return cred_ex_record

    async def receive_proposal(
        self, message: CredentialProposal, connection_id: str
    ) -> V10CredentialExchange:
        """
        Receive a credential proposal.

        Returns:
            The resulting credential exchange record, created

        """
        # at this point, cred def and schema still open to potential negotiation
        cred_ex_record = V10CredentialExchange(
            connection_id=connection_id,
            thread_id=message._thread_id,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_PROPOSAL_RECEIVED,
            credential_proposal_dict=message,
            auto_offer=self._profile.settings.get(
                "debug.auto_respond_credential_proposal"
            ),
            auto_issue=self._profile.settings.get(
                "debug.auto_respond_credential_request"
            ),
            auto_remove=not self._profile.settings.get("preserve_exchange_records"),
            trace=(message._trace is not None),
        )
        async with self._profile.session() as session:
            await cred_ex_record.save(session, reason="receive credential proposal")

        return cred_ex_record

    async def create_offer(
        self,
        cred_ex_record: V10CredentialExchange,
        counter_proposal: CredentialProposal = None,
        comment: str = None,
    ) -> Tuple[V10CredentialExchange, CredentialOffer]:
        """
        Create a credential offer, update credential exchange record.

        Args:
            cred_ex_record: Credential exchange to create offer for
            comment: optional human-readable comment to set in offer message

        Returns:
            A tuple (credential exchange record, credential offer message)

        """

        async def _create(cred_def_id):
            issuer = self._profile.inject(IndyIssuer)
            offer_json = await issuer.create_credential_offer(cred_def_id)
            return json.loads(offer_json)

        credential_proposal_message = (
            counter_proposal
            if counter_proposal
            else cred_ex_record.credential_proposal_dict
        )
        credential_proposal_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )
        cred_def_id = await self._match_sent_cred_def_id(
            {
                t: getattr(credential_proposal_message, t)
                for t in CRED_DEF_TAGS
                if getattr(credential_proposal_message, t)
            }
        )

        credential_preview = credential_proposal_message.credential_proposal

        # vet attributes
        ledger = self._profile.inject(BaseLedger)
        async with ledger:
            schema_id = await ledger.credential_definition_id2schema_id(cred_def_id)
            schema = await ledger.get_schema(schema_id)
        schema_attrs = {attr for attr in schema["attrNames"]}
        preview_attrs = {attr for attr in credential_preview.attr_dict()}
        if preview_attrs != schema_attrs:
            raise CredentialManagerError(
                f"Preview attributes {preview_attrs} "
                f"mismatch corresponding schema attributes {schema_attrs}"
            )

        credential_offer = None
        cache_key = f"credential_offer::{cred_def_id}"
        cache = self._profile.inject_or(BaseCache)
        if cache:
            async with cache.acquire(cache_key) as entry:
                if entry.result:
                    credential_offer = entry.result
                else:
                    credential_offer = await _create(cred_def_id)
                    await entry.set_result(credential_offer, 3600)
        if not credential_offer:
            credential_offer = await _create(cred_def_id)

        credential_offer_message = CredentialOffer(
            comment=comment,
            credential_preview=credential_preview,
            offers_attach=[CredentialOffer.wrap_indy_offer(credential_offer)],
        )

        credential_offer_message._thread = {"thid": cred_ex_record.thread_id}
        credential_offer_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        cred_ex_record.thread_id = credential_offer_message._thread_id
        cred_ex_record.schema_id = credential_offer["schema_id"]
        cred_ex_record.credential_definition_id = credential_offer["cred_def_id"]
        cred_ex_record.state = V10CredentialExchange.STATE_OFFER_SENT
        cred_ex_record.credential_proposal_dict = (  # any counter replaces original
            credential_proposal_message
        )
        cred_ex_record.credential_offer = credential_offer

        cred_ex_record.credential_offer_dict = credential_offer_message

        async with self._profile.session() as session:
            await cred_ex_record.save(session, reason="create credential offer")

        return (cred_ex_record, credential_offer_message)

    async def receive_offer(
        self, message: CredentialOffer, connection_id: str
    ) -> V10CredentialExchange:
        """
        Receive a credential offer.

        Returns:
            The credential exchange record, updated

        """
        credential_preview = message.credential_preview
        indy_offer = message.indy_offer(0)
        schema_id = indy_offer["schema_id"]
        cred_def_id = indy_offer["cred_def_id"]

        credential_proposal_dict = CredentialProposal(
            comment=message.comment,
            credential_proposal=credential_preview,
            schema_id=schema_id,
            cred_def_id=cred_def_id,
        )

        async with self._profile.session() as session:
            # Get credential exchange record (holder sent proposal first)
            # or create it (issuer sent offer first)
            try:
                cred_ex_record = await (
                    V10CredentialExchange.retrieve_by_connection_and_thread(
                        session, connection_id, message._thread_id
                    )
                )
                cred_ex_record.credential_proposal_dict = credential_proposal_dict
            except StorageNotFoundError:  # issuer sent this offer free of any proposal
                cred_ex_record = V10CredentialExchange(
                    connection_id=connection_id,
                    thread_id=message._thread_id,
                    initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
                    role=V10CredentialExchange.ROLE_HOLDER,
                    credential_proposal_dict=credential_proposal_dict,
                    auto_remove=not self._profile.settings.get(
                        "preserve_exchange_records"
                    ),
                    trace=(message._trace is not None),
                )

            cred_ex_record.credential_offer = indy_offer
            cred_ex_record.state = V10CredentialExchange.STATE_OFFER_RECEIVED
            cred_ex_record.schema_id = schema_id
            cred_ex_record.credential_definition_id = cred_def_id

            await cred_ex_record.save(session, reason="receive credential offer")

        return cred_ex_record

    async def create_request(
        self, cred_ex_record: V10CredentialExchange, holder_did: str
    ) -> Tuple[V10CredentialExchange, CredentialRequest]:
        """
        Create a credential request.

        Args:
            cred_ex_record: Credential exchange record
                for which to create request
            holder_did: holder DID

        Returns:
            A tuple (credential exchange record, credential request message)

        """
        if cred_ex_record.state != V10CredentialExchange.STATE_OFFER_RECEIVED:
            raise CredentialManagerError(
                f"Credential exchange {cred_ex_record.credential_exchange_id} "
                f"in {cred_ex_record.state} state "
                f"(must be {V10CredentialExchange.STATE_OFFER_RECEIVED})"
            )

        credential_definition_id = cred_ex_record.credential_definition_id
        cred_offer_ser = cred_ex_record._credential_offer.ser

        async def _create():
            ledger = self._profile.inject(BaseLedger)
            async with ledger:
                credential_definition = await ledger.get_credential_definition(
                    credential_definition_id
                )

            holder = self._profile.inject(IndyHolder)
            request_json, metadata_json = await holder.create_credential_request(
                cred_offer_ser,
                credential_definition,
                holder_did,
            )
            return {
                "request": json.loads(request_json),
                "metadata": json.loads(metadata_json),
            }

        if cred_ex_record.credential_request:
            LOGGER.warning(
                "create_request called multiple times for v1.0 credential exchange: %s",
                cred_ex_record.credential_exchange_id,
            )
        else:
            nonce = cred_offer_ser["nonce"]
            cache_key = (
                f"credential_request::{credential_definition_id}::{holder_did}::{nonce}"
            )
            cred_req_result = None
            cache = self._profile.inject_or(BaseCache)
            if cache:
                async with cache.acquire(cache_key) as entry:
                    if entry.result:
                        cred_req_result = entry.result
                    else:
                        cred_req_result = await _create()
                        await entry.set_result(cred_req_result, 3600)
            if not cred_req_result:
                cred_req_result = await _create()

            (
                cred_ex_record.credential_request,
                cred_ex_record.credential_request_metadata,
            ) = (cred_req_result["request"], cred_req_result["metadata"])

        credential_request_message = CredentialRequest(
            requests_attach=[
                CredentialRequest.wrap_indy_cred_req(
                    cred_ex_record._credential_request.ser
                )
            ]
        )
        credential_request_message._thread = {"thid": cred_ex_record.thread_id}
        credential_request_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        cred_ex_record.state = V10CredentialExchange.STATE_REQUEST_SENT
        async with self._profile.session() as session:
            await cred_ex_record.save(session, reason="create credential request")

        return (cred_ex_record, credential_request_message)

    async def receive_request(self, message: CredentialRequest, connection_id: str):
        """
        Receive a credential request.

        Args:
            credential_request_message: Credential request to receive

        Returns:
            credential exchange record, retrieved and updated

        """
        assert len(message.requests_attach or []) == 1
        credential_request = message.indy_cred_req(0)

        async with self._profile.session() as session:
            try:
                cred_ex_record = await (
                    V10CredentialExchange.retrieve_by_connection_and_thread(
                        session, connection_id, message._thread_id
                    )
                )
            except StorageNotFoundError:
                try:
                    cred_ex_record = await V10CredentialExchange.retrieve_by_tag_filter(
                        session,
                        {"thread_id": message._thread_id},
                        {"connection_id": None},
                    )
                    cred_ex_record.connection_id = connection_id
                except StorageNotFoundError:
                    raise CredentialManagerError(
                        "Indy issue credential format can't start from credential request"
                    )
            cred_ex_record.credential_request = credential_request
            cred_ex_record.state = V10CredentialExchange.STATE_REQUEST_RECEIVED
            await cred_ex_record.save(session, reason="receive credential request")

        return cred_ex_record

    async def issue_credential(
        self,
        cred_ex_record: V10CredentialExchange,
        *,
        comment: str = None,
        retries: int = 5,
    ) -> Tuple[V10CredentialExchange, CredentialIssue]:
        """
        Issue a credential.

        Args:
            cred_ex_record: The credential exchange record
                for which to issue a credential
            comment: optional human-readable comment pertaining to credential issue

        Returns:
            Tuple: (Updated credential exchange record, credential message)

        """

        if cred_ex_record.state != V10CredentialExchange.STATE_REQUEST_RECEIVED:
            raise CredentialManagerError(
                f"Credential exchange {cred_ex_record.credential_exchange_id} "
                f"in {cred_ex_record.state} state "
                f"(must be {V10CredentialExchange.STATE_REQUEST_RECEIVED})"
            )

        schema_id = cred_ex_record.schema_id
        rev_reg = None

        if cred_ex_record.credential:
            LOGGER.warning(
                "issue_credential called multiple times for "
                + "credential exchange record %s - abstaining",
                cred_ex_record.credential_exchange_id,
            )
        else:
            cred_offer_ser = cred_ex_record._credential_offer.ser
            cred_req_ser = cred_ex_record._credential_request.ser

            ledger = self._profile.inject(BaseLedger)
            async with ledger:
                schema = await ledger.get_schema(schema_id)
                credential_definition = await ledger.get_credential_definition(
                    cred_ex_record.credential_definition_id
                )

            tails_path = None
            if credential_definition["value"].get("revocation"):
                revoc = IndyRevocation(self._profile)
                try:
                    active_rev_reg_rec = await revoc.get_active_issuer_rev_reg_record(
                        cred_ex_record.credential_definition_id
                    )
                    rev_reg = await active_rev_reg_rec.get_registry()
                    cred_ex_record.revoc_reg_id = active_rev_reg_rec.revoc_reg_id

                    tails_path = rev_reg.tails_local_path
                    await rev_reg.get_or_fetch_local_tails_path()

                except StorageNotFoundError:
                    async with self._profile.session() as session:
                        posted_rev_reg_recs = (
                            await IssuerRevRegRecord.query_by_cred_def_id(
                                session,
                                cred_ex_record.credential_definition_id,
                                state=IssuerRevRegRecord.STATE_POSTED,
                            )
                        )
                    if not posted_rev_reg_recs:
                        # Send next 2 rev regs, publish tails files in background
                        async with self._profile.session() as session:
                            old_rev_reg_recs = sorted(
                                await IssuerRevRegRecord.query_by_cred_def_id(
                                    session,
                                    cred_ex_record.credential_definition_id,
                                )
                            )  # prefer to reuse prior rev reg size
                        cred_def_id = cred_ex_record.credential_definition_id
                        rev_reg_size = (
                            old_rev_reg_recs[0].max_cred_num
                            if old_rev_reg_recs
                            else None
                        )
                        for _ in range(2):
                            await notify_revocation_reg_event(
                                self.profile,
                                cred_def_id,
                                rev_reg_size,
                                auto_create_rev_reg=True,
                            )

                    if retries > 0:
                        LOGGER.info(
                            "Waiting 2s on posted rev reg for cred def %s, retrying",
                            cred_ex_record.credential_definition_id,
                        )
                        await asyncio.sleep(2)
                        return await self.issue_credential(
                            cred_ex_record=cred_ex_record,
                            comment=comment,
                            retries=retries - 1,
                        )

                    raise CredentialManagerError(
                        f"Cred def id {cred_ex_record.credential_definition_id} "
                        "has no active revocation registry"
                    )
                del revoc

            credential_values = (
                cred_ex_record.credential_proposal_dict.credential_proposal.attr_dict(
                    decode=False
                )
            )
            issuer = self._profile.inject(IndyIssuer)
            try:
                (
                    credential_json,
                    cred_ex_record.revocation_id,
                ) = await issuer.create_credential(
                    schema,
                    cred_offer_ser,
                    cred_req_ser,
                    credential_values,
                    cred_ex_record.credential_exchange_id,
                    cred_ex_record.revoc_reg_id,
                    tails_path,
                )

                # If the rev reg is now full
                if rev_reg and rev_reg.max_creds == int(cred_ex_record.revocation_id):
                    async with self._profile.session() as session:
                        await active_rev_reg_rec.set_state(
                            session,
                            IssuerRevRegRecord.STATE_FULL,
                        )

                    # Send next 1 rev reg, publish tails file in background
                    cred_def_id = cred_ex_record.credential_definition_id
                    rev_reg_size = active_rev_reg_rec.max_cred_num
                    await notify_revocation_reg_event(
                        self.profile,
                        cred_def_id,
                        rev_reg_size,
                        auto_create_rev_reg=True,
                    )

            except IndyIssuerRevocationRegistryFullError:
                # unlucky: duelling instance issued last cred near same time as us
                async with self._profile.session() as session:
                    await active_rev_reg_rec.set_state(
                        session,
                        IssuerRevRegRecord.STATE_FULL,
                    )

                if retries > 0:
                    # use next rev reg; at worst, lucky instance is putting one up
                    LOGGER.info(
                        "Waiting 1s and retrying: revocation registry %s is full",
                        active_rev_reg_rec.revoc_reg_id,
                    )
                    await asyncio.sleep(1)
                    return await self.issue_credential(
                        cred_ex_record=cred_ex_record,
                        comment=comment,
                        retries=retries - 1,
                    )

                raise

            cred_ex_record.credential = json.loads(credential_json)

        cred_ex_record.state = V10CredentialExchange.STATE_ISSUED
        async with self._profile.session() as session:
            # FIXME - re-fetch record to check state, apply transactional update
            await cred_ex_record.save(session, reason="issue credential")

        credential_message = CredentialIssue(
            comment=comment,
            credentials_attach=[
                CredentialIssue.wrap_indy_credential(cred_ex_record._credential.ser)
            ],
        )
        credential_message._thread = {"thid": cred_ex_record.thread_id}
        credential_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        return (cred_ex_record, credential_message)

    async def receive_credential(
        self, message: CredentialIssue, connection_id: str
    ) -> V10CredentialExchange:
        """
        Receive a credential from an issuer.

        Hold in storage potentially to be processed by controller before storing.

        Returns:
            Credential exchange record, retrieved and updated

        """
        assert len(message.credentials_attach or []) == 1
        raw_credential = message.indy_credential(0)

        # FIXME use transaction, fetch for_update
        async with self._profile.session() as session:
            cred_ex_record = await (
                V10CredentialExchange.retrieve_by_connection_and_thread(
                    session,
                    connection_id,
                    message._thread_id,
                )
            )

            cred_ex_record.raw_credential = raw_credential
            cred_ex_record.state = V10CredentialExchange.STATE_CREDENTIAL_RECEIVED

            await cred_ex_record.save(session, reason="receive credential")
        return cred_ex_record

    async def store_credential(
        self, cred_ex_record: V10CredentialExchange, credential_id: str = None
    ) -> V10CredentialExchange:
        """
        Store a credential in holder wallet; send ack to issuer.

        Args:
            cred_ex_record: credential exchange record
                with credential to store and ack
            credential_id: optional credential identifier to override default on storage

        Returns:
            Updated credential exchange record

        """
        if cred_ex_record.state != (V10CredentialExchange.STATE_CREDENTIAL_RECEIVED):
            raise CredentialManagerError(
                f"Credential exchange {cred_ex_record.credential_exchange_id} "
                f"in {cred_ex_record.state} state "
                f"(must be {V10CredentialExchange.STATE_CREDENTIAL_RECEIVED})"
            )

        raw_cred_serde = cred_ex_record._raw_credential
        revoc_reg_def = None
        ledger = self._profile.inject(BaseLedger)
        async with ledger:
            credential_definition = await ledger.get_credential_definition(
                raw_cred_serde.de.cred_def_id
            )
            if raw_cred_serde.de.rev_reg_id:
                revoc_reg_def = await ledger.get_revoc_reg_def(
                    raw_cred_serde.de.rev_reg_id
                )

        holder = self._profile.inject(IndyHolder)
        if (
            cred_ex_record.credential_proposal_dict
            and cred_ex_record.credential_proposal_dict.credential_proposal
        ):
            mime_types = (
                cred_ex_record.credential_proposal_dict.credential_proposal.mime_types()
            )
        else:
            mime_types = None

        if revoc_reg_def:
            revoc_reg = RevocationRegistry.from_definition(revoc_reg_def, True)
            await revoc_reg.get_or_fetch_local_tails_path()
        try:
            credential_id = await holder.store_credential(
                credential_definition,
                raw_cred_serde.ser,
                cred_ex_record.credential_request_metadata,
                mime_types,
                credential_id=credential_id,
                rev_reg_def=revoc_reg_def,
            )
        except IndyHolderError as e:
            LOGGER.error(f"Error storing credential. {e.error_code}: {e.message}")
            raise e

        credential_json = await holder.get_credential(credential_id)
        credential = json.loads(credential_json)

        cred_ex_record.credential_id = credential_id
        cred_ex_record.credential = credential
        cred_ex_record.revoc_reg_id = credential.get("rev_reg_id", None)
        cred_ex_record.revocation_id = credential.get("cred_rev_id", None)

        async with self._profile.session() as session:
            # FIXME - re-fetch record to check state, apply transactional update
            await cred_ex_record.save(session, reason="store credential")

        return cred_ex_record

    async def send_credential_ack(
        self,
        cred_ex_record: V10CredentialExchange,
    ):
        """
        Create, send, and return ack message for input credential exchange record.

        Delete credential exchange record if set to auto-remove.

        Returns:
            Tuple: cred ex record, credential ack message for tracing.

        """
        credential_ack_message = CredentialAck()
        credential_ack_message.assign_thread_id(
            cred_ex_record.thread_id, cred_ex_record.parent_thread_id
        )
        credential_ack_message.assign_trace_decorator(
            self._profile.settings, cred_ex_record.trace
        )

        cred_ex_record.state = V10CredentialExchange.STATE_ACKED
        try:
            async with self._profile.session() as session:
                # FIXME - re-fetch record to check state, apply transactional update
                await cred_ex_record.save(session, reason="ack credential")

                if cred_ex_record.auto_remove:
                    await cred_ex_record.delete_record(session)  # all done: delete

        except StorageError as err:
            LOGGER.exception(err)  # holder still owes an ack: carry on

        responder = self._profile.inject_or(BaseResponder)
        if responder:
            await responder.send_reply(
                credential_ack_message,
                connection_id=cred_ex_record.connection_id,
            )
        else:
            LOGGER.warning(
                "Configuration has no BaseResponder: cannot ack credential on %s",
                cred_ex_record.thread_id,
            )

        return cred_ex_record, credential_ack_message

    async def receive_credential_ack(
        self, message: CredentialAck, connection_id: str
    ) -> V10CredentialExchange:
        """
        Receive credential ack from holder.

        Returns:
            credential exchange record, retrieved and updated

        """
        # FIXME use transaction, fetch for_update
        async with self._profile.session() as session:
            cred_ex_record = await (
                V10CredentialExchange.retrieve_by_connection_and_thread(
                    session,
                    connection_id,
                    message._thread_id,
                )
            )

            cred_ex_record.state = V10CredentialExchange.STATE_ACKED
            await cred_ex_record.save(session, reason="credential acked")

        if cred_ex_record.auto_remove:
            async with self._profile.session() as session:
                await cred_ex_record.delete_record(session)  # all done: delete

        return cred_ex_record

    async def receive_problem_report(
        self, message: CredentialProblemReport, connection_id: str
    ):
        """
        Receive problem report.

        Returns:
            credential exchange record, retrieved and updated

        """
        # FIXME use transaction, fetch for_update
        async with self._profile.session() as session:
            cred_ex_record = await (
                V10CredentialExchange.retrieve_by_connection_and_thread(
                    session,
                    connection_id,
                    message._thread_id,
                )
            )

            cred_ex_record.state = None
            code = message.description.get(
                "code",
                ProblemReportReason.ISSUANCE_ABANDONED.value,
            )
            cred_ex_record.error_msg = f"{code}: {message.description.get('en', code)}"
            await cred_ex_record.save(session, reason="received problem report")

        return cred_ex_record
