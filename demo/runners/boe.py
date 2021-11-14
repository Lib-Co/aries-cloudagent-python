import asyncio
import json
import logging
import os
import sys
import time
import datetime

from aiohttp import ClientError
from qrcode import QRCode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.agent import (  # noqa:E402
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)


CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class BoEAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        endorser_role: str = None,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="boe",
            no_auto=no_auto,
            endorser_role=endorser_role,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # TODO define a dict to hold credential attributes
        # based on cred_def_id
        self.cred_attrs = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        age = 24
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
        if aip == 10:
            # define attributes to send for credential
            self.cred_attrs[cred_def_id] = {
                "name": "Alice Smith",
                "date": "2018-05-28",
                "identification": "Maths",
                "birthdate_dateint": birth_date.strftime(birth_date_format),
                "timestamp": str(int(time.time())),
            }

            cred_preview = {
                "@type": CRED_PREVIEW_TYPE,
                "attributes": [
                    {"name": n, "value": v}
                    for (n, v) in self.cred_attrs[cred_def_id].items()
                ],
            }
            offer_request = {
                "connection_id": self.connection_id,
                "cred_def_id": cred_def_id,
                "comment": f"Offer on cred def id {cred_def_id}",
                "auto_remove": False,
                "credential_preview": cred_preview,
                "trace": exchange_tracing,
            }
            return offer_request

        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                self.cred_attrs[cred_def_id] = {
                    "name": "Alice Smith",
                    "date": "2018-05-28",
                    "identification": "Maths",
                    "birthdate_dateint": birth_date.strftime(birth_date_format),
                    "timestamp": str(int(time.time())),
                }

                cred_preview = {
                    "@type": CRED_PREVIEW_TYPE,
                    "attributes": [
                        {"name": n, "value": v}
                        for (n, v) in self.cred_attrs[cred_def_id].items()
                    ],
                }
                offer_request = {
                    "connection_id": self.connection_id,
                    "comment": f"Offer on cred def id {cred_def_id}",
                    "auto_remove": False,
                    "credential_preview": cred_preview,
                    "filter": {"indy": {"cred_def_id": cred_def_id}},
                    "trace": exchange_tracing,
                }
                return offer_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                offer_request = {
                    "connection_id": self.connection_id,
                    "filter": {
                        "ld_proof": {
                            "credential": {
                                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://w3id.org/citizenship/v1",
                                    "https://w3id.org/security/bbs/v1",
                                ],
                                "type": [
                                    "VerifiableCredential",
                                    "PermanentResident",
                                ],
                                "id": "https://credential.example.com/residents/1234567890",
                                "issuer": self.did,
                                "issuanceDate": "2020-01-01T12:00:00Z",
                                "credentialSubject": {
                                    "type": ["PermanentResident"],
                                    "givenName": "ALICE",
                                    "familyName": "SMITH",
                                    "gender": "Female",
                                    "birthCountry": "Bahamas",
                                    "birthDate": "1958-07-17",
                                },
                            },
                            "options": {"proofType": SIG_TYPE_BLS},
                        }
                    },
                }
                return offer_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

    def generate_proof_request_web_request(
        self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        age = 18
        d = datetime.date.today()
        birth_date = datetime.date(d.year - age, d.month, d.day)
        birth_date_format = "%Y%m%d"
        if aip == 10:
            req_attrs = [
                {
                    "name": "name",
                    "restrictions": [{"schema_name": "identification schema"}],
                },
                {
                    "name": "date",
                    "restrictions": [{"schema_name": "identification schema"}],
                },
            ]
            if revocation:
                req_attrs.append(
                    {
                        "name": "identification",
                        "restrictions": [{"schema_name": "identification schema"}],
                        "non_revoked": {"to": int(time.time() - 1)},
                    },
                )
            else:
                req_attrs.append(
                    {
                        "name": "identification",
                        "restrictions": [{"schema_name": "identification schema"}],
                    }
                )
            if SELF_ATTESTED:
                # test self-attested claims
                req_attrs.append(
                    {"name": "self_attested_thing"},
                )
            req_preds = [
                # test zero-knowledge proofs
                {
                    "name": "birthdate_dateint",
                    "p_type": "<=",
                    "p_value": int(birth_date.strftime(birth_date_format)),
                    "restrictions": [{"schema_name": "identification schema"}],
                }
            ]
            indy_proof_request = {
                "name": "Proof of Education",
                "version": "1.0",
                "requested_attributes": {
                    f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                },
                "requested_predicates": {
                    f"0_{req_pred['name']}_GE_uuid": req_pred for req_pred in req_preds
                },
            }

            if revocation:
                indy_proof_request["non_revoked"] = {"to": int(time.time())}

            proof_request_web_request = {
                "proof_request": indy_proof_request,
                "trace": exchange_tracing,
            }
            if not connectionless:
                proof_request_web_request["connection_id"] = self.connection_id
            return proof_request_web_request

        elif aip == 20:
            if cred_type == CRED_FORMAT_INDY:
                req_attrs = [
                    {
                "host": "localhost",
                        "name": "name",
                        "restrictions": [{"schema_name": "identification schema"}],
                    },
                    {
                        "name": "date",
                        "restrictions": [{"schema_name": "identification schema"}],
                    },
                ]
                if revocation:
                    req_attrs.append(
                        {
                            "name": "identification",
                            "restrictions": [{"schema_name": "identification schema"}],
                            "non_revoked": {"to": int(time.time() - 1)},
                        },
                    )
                else:
                    req_attrs.append(
                        {
                            "name": "identification",
                            "restrictions": [{"schema_name": "identification schema"}],
                        }
                    )
                if SELF_ATTESTED:
                    # test self-attested claims
                    req_attrs.append(
                        {"name": "self_attested_thing"},
                    )
                req_preds = [
                    # test zero-knowledge proofs
                    {
                        "name": "birthdate_dateint",
                        "p_type": "<=",
                        "p_value": int(birth_date.strftime(birth_date_format)),
                        "restrictions": [{"schema_name": "identification schema"}],
                    }
                ]
                indy_proof_request = {
                    "name": "Proof of Education",
                    "version": "1.0",
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                    },
                    "requested_predicates": {
                        f"0_{req_pred['name']}_GE_uuid": req_pred
                        for req_pred in req_preds
                    },
                }

                if revocation:
                    indy_proof_request["non_revoked"] = {"to": int(time.time())}

                proof_request_web_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                proof_request_web_request = {
                    "comment": "test proof request for json-ld",
                    "presentation_request": {
                        "dif": {
                            "options": {
                                "challenge": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
                                "domain": "4jt78h47fh47",
                            },
                            "presentation_definition": {
                                "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
                                "format": {"ldp_vp": {"proof_type": [SIG_TYPE_BLS]}},
                                "input_descriptors": [
                                    {
                                        "id": "citizenship_input_1",
                                        "name": "EU Driver's License",
                                        "schema": [
                                            {
                                                "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
                                            },
                                            {
                                                "uri": "https://w3id.org/citizenship#PermanentResident"
                                            },
                                        ],
                                        "constraints": {
                                            "limit_disclosure": "required",
                                            "is_holder": [
                                                {
                                                    "directive": "required",
                                                    "field_id": [
                                                        "1f44d55f-f161-4938-a659-f8026467f126"
                                                    ],
                                                }
                                            ],
                                            "fields": [
                                                {
                                                    "id": "1f44d55f-f161-4938-a659-f8026467f126",
                                                    "path": [
                                                        "$.credentialSubject.familyName"
                                                    ],
                                                    "purpose": "The claim must be from one of the specified person",
                                                    "filter": {"const": "SMITH"},
                                                },
                                                {
                                                    "path": [
                                                        "$.credentialSubject.givenName"
                                                    ],
                                                    "purpose": "The claim must be from one of the specified person",
                                                },
                                            ],
                                        },
                                    }
                                ],
                            },
                        }
                    },
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")


async def main(args):
    boe_agent = await create_agent_with_args(args, ident="boe")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {boe_agent.wallet_type})"
                if boe_agent.wallet_type
                else ""
            )
        )
        agent = BoEAgent(
            "boe.agent",
            boe_agent.start_port,
            boe_agent.start_port + 1,
            genesis_data=boe_agent.genesis_txns,
            no_auto=boe_agent.no_auto,
            tails_server_base_url=boe_agent.tails_server_base_url,
            timing=boe_agent.show_timing,
            multitenant=boe_agent.multitenant,
            mediation=boe_agent.mediation,
            wallet_type=boe_agent.wallet_type,
            seed=boe_agent.seed,
            aip=boe_agent.aip,
            endorser_role=boe_agent.endorser_role,
        )

        boe_schema_name = "identification schema"
        boe_schema_attrs = [
            "name",
            "date",
            "identification",
            "birthdate_dateint",
            "timestamp",
        ]
        if boe_agent.cred_type == CRED_FORMAT_INDY:
            boe_agent.public_did = True
            await boe_agent.initialize(
                the_agent=agent,
                schema_name=boe_schema_name,
                schema_attrs=boe_schema_attrs,
                create_endorser_agent=(boe_agent.endorser_role == "author")
                if boe_agent.endorser_role
                else False,
            )
        elif boe_agent.cred_type == CRED_FORMAT_JSON_LD:
            boe_agent.public_did = True
            await boe_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + boe_agent.cred_type)

        # generate an invitation for beeds_user
        await boe_agent.generate_invitation(display_qr=True, wait=True)

        exchange_tracing = False
        options = (
            "    (1) Issue Credential\n"
            "    (2) Send Proof Request\n"
            "    (2a) Send *Connectionless* Proof Request (requires a Mobile client)\n"
            "    (3) Send Message\n"
            "    (4) Create New Invitation\n"
        )
        if boe_agent.revocation:
            options += "    (5) Revoke Credential\n" "    (6) Publish Revocations\n"
        if boe_agent.endorser_role and boe_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if boe_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (T) Toggle tracing on credential/proof exchange\n"
        options += "    (X) Exit?\n[1/2/3/4/{}{}T/X] ".format(
            "5/6/" if boe_agent.revocation else "",
            "W/" if boe_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and boe_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await boe_agent.agent.admin_POST(
                    f"/transactions/{boe_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did},
                )

            elif option in "wW" and boe_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    created = await boe_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=boe_agent.agent.get_new_webhook_port(),
                        public_did=True,
                        mediator_agent=boe_agent.mediator_agent,
                        endorser_agent=boe_agent.endorser_agent,
                    )
                else:
                    created = await boe_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        public_did=True,
                        mediator_agent=boe_agent.mediator_agent,
                        endorser_agent=boe_agent.endorser_agent,
                        cred_type=boe_agent.cred_type,
                    )
                # create a schema and cred def for the new wallet
                # TODO check first in case we are switching between existing wallets
                if created:
                    # TODO this fails because the new wallet doesn't get a public DID
                    await boe_agent.create_schema_and_cred_def(
                        schema_name=boe_schema_name,
                        schema_attrs=boe_schema_attrs,
                    )

            elif option in "tT":
                exchange_tracing = not exchange_tracing
                log_msg(
                    ">>> Credential/Proof Exchange Tracing is {}".format(
                        "ON" if exchange_tracing else "OFF"
                    )
                )

            elif option == "1":
                log_status("#13 Issue credential offer to X")

                if boe_agent.aip == 10:
                    offer_request = boe_agent.agent.generate_credential_offer(
                        boe_agent.aip, None, boe_agent.cred_def_id, exchange_tracing
                    )
                    await boe_agent.agent.admin_POST(
                        "/issue-credential/send-offer", offer_request
                    )

                elif boe_agent.aip == 20:
                    if boe_agent.cred_type == CRED_FORMAT_INDY:
                        offer_request = boe_agent.agent.generate_credential_offer(
                            boe_agent.aip,
                            boe_agent.cred_type,
                            boe_agent.cred_def_id,
                            exchange_tracing,
                        )

                    elif boe_agent.cred_type == CRED_FORMAT_JSON_LD:
                        offer_request = boe_agent.agent.generate_credential_offer(
                            boe_agent.aip,
                            boe_agent.cred_type,
                            None,
                            exchange_tracing,
                        )

                    else:
                        raise Exception(
                            f"Error invalid credential type: {boe_agent.cred_type}"
                        )

                    await boe_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {boe_agent.aip}")

            elif option == "2":
                log_status("#20 Request proof of identification from beeds_user")
                if boe_agent.aip == 10:
                    proof_request_web_request = (
                        boe_agent.agent.generate_proof_request_web_request(
                            boe_agent.aip,
                            boe_agent.cred_type,
                            boe_agent.revocation,
                            exchange_tracing,
                        )
                    )
                    await boe_agent.agent.admin_POST(
                        "/present-proof/send-request", proof_request_web_request
                    )
                    pass

                elif boe_agent.aip == 20:
                    if boe_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            boe_agent.agent.generate_proof_request_web_request(
                                boe_agent.aip,
                                boe_agent.cred_type,
                                boe_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    elif boe_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            boe_agent.agent.generate_proof_request_web_request(
                                boe_agent.aip,
                                boe_agent.cred_type,
                                boe_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    else:
                        raise Exception(
                            "Error invalid credential type:" + boe_agent.cred_type
                        )

                    await agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {boe_agent.aip}")

            elif option == "2a":
                log_status("#20 Request * Connectionless * proof of identification from beeds_user")
                if boe_agent.aip == 10:
                    proof_request_web_request = (
                        boe_agent.agent.generate_proof_request_web_request(
                            boe_agent.aip,
                            boe_agent.cred_type,
                            boe_agent.revocation,
                            exchange_tracing,
                            connectionless=True,
                        )
                    )
                    proof_request = await boe_agent.agent.admin_POST(
                        "/present-proof/create-request", proof_request_web_request
                    )
                    pres_req_id = proof_request["presentation_exchange_id"]
                    url = (
                        "http://"
                        + os.getenv("DOCKERHOST").replace(
                            "{PORT}", str(boe_agent.agent.admin_port + 1)
                        )
                        + "/webhooks/pres_req/"
                        + pres_req_id
                        + "/"
                    )
                    log_msg(f"Proof request url: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg(
                        "Scan the following QR code to accept the proof request from a mobile agent."
                    )
                    qr.print_ascii(invert=True)

                elif boe_agent.aip == 20:
                    if boe_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            boe_agent.agent.generate_proof_request_web_request(
                                boe_agent.aip,
                                boe_agent.cred_type,
                                boe_agent.revocation,
                                exchange_tracing,
                                connectionless=True,
                            )
                        )
                    elif boe_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            boe_agent.agent.generate_proof_request_web_request(
                                boe_agent.aip,
                                boe_agent.cred_type,
                                boe_agent.revocation,
                                exchange_tracing,
                                connectionless=True,
                            )
                        )
                    else:
                        raise Exception(
                            "Error invalid credential type:" + boe_agent.cred_type
                        )

                    proof_request = await boe_agent.agent.admin_POST(
                        "/present-proof-2.0/create-request", proof_request_web_request
                    )
                    pres_req_id = proof_request["pres_ex_id"]
                    url = (
                        "http://"
                        + os.getenv("DOCKERHOST").replace(
                            "{PORT}", str(boe_agent.agent.admin_port + 1)
                        )
                        + "/webhooks/pres_req/"
                        + pres_req_id
                        + "/"
                    )
                    log_msg(f"Proof request url: {url}")
                    qr = QRCode(border=1)
                    qr.add_data(url)
                    log_msg(
                        "Scan the following QR code to accept the proof request from a mobile agent."
                    )
                    qr.print_ascii(invert=True)
                else:
                    raise Exception(f"Error invalid AIP level: {boe_agent.aip}")

            elif option == "3":
                msg = await prompt("Enter message: ")
                await boe_agent.agent.admin_POST(
                    f"/connections/{boe_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "4":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using beeds_user agent"
                )
                await boe_agent.generate_invitation(display_qr=True, wait=True)

            elif option == "5" and boe_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                    await prompt("Publish now? [Y/N]: ", default="N")
                ).strip() in "yY"
                try:
                    await boe_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                        },
                    )
                except ClientError:
                    pass

            elif option == "6" and boe_agent.revocation:
                try:
                    resp = await boe_agent.agent.admin_POST(
                        "/revocation/publish-revocations", {}
                    )
                    boe_agent.agent.log(
                        "Published revocations for {} revocation registr{} {}".format(
                            len(resp["rrid2crid"]),
                            "y" if len(resp["rrid2crid"]) == 1 else "ies",
                            json.dumps([k for k in resp["rrid2crid"]], indent=4),
                        )
                    )
                except ClientError:
                    pass

        if boe_agent.show_timing:
            timing = await boe_agent.agent.fetch_timing()
            if timing:
                for line in boe_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await boe_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="boe", port=8020)
    args = parser.parse_args()

    ENABLE_PTVSD = os.getenv("ENABLE_PTVSD_FABER", "").lower()
    ENABLE_PTVSD = ENABLE_PTVSD and ENABLE_PTVSD not in ("false", "0")

    ENABLE_PYDEVD_PYCHARM = os.getenv("ENABLE_PYDEVD_PYCHARM", "").lower()
    ENABLE_PYDEVD_PYCHARM = ENABLE_PYDEVD_PYCHARM and ENABLE_PYDEVD_PYCHARM not in (
        "false",
        "0",
    )
    PYDEVD_PYCHARM_HOST = os.getenv("PYDEVD_PYCHARM_HOST", "localhost")
    PYDEVD_PYCHARM_CONTROLLER_PORT = int(
        os.getenv("PYDEVD_PYCHARM_CONTROLLER_PORT", 5001)
    )
    # --debug to use microsoft's visual studio remote debugger
    if ENABLE_PTVSD or "--debug" in args:
        try:
            import ptvsd

            ptvsd.enable_attach(address = ('0.0.0.0', 5679))
            print("ptvsd is running")
            print("=== Waiting for debugger to attach ===")
            # To pause execution until the debugger is attached:
            ptvsd.wait_for_attach()
        except ImportError:
            print("ptvsd library was not found")

    if ENABLE_PYDEVD_PYCHARM:
        try:
            import pydevd_pycharm

            print(
                "boe remote debugging to "
                f"{PYDEVD_PYCHARM_HOST}:{PYDEVD_PYCHARM_CONTROLLER_PORT}"
            )
            pydevd_pycharm.settrace(
                host=PYDEVD_PYCHARM_HOST,
                port=PYDEVD_PYCHARM_CONTROLLER_PORT,
                stdoutToServer=True,
                stderrToServer=True,
                suspend=False,
            )
        except ImportError:
            print("pydevd_pycharm library was not found")

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)