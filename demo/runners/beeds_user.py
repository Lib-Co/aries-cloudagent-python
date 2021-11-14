import asyncio
import base64
import binascii
import json
import logging
import os
import sys
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class BEEDSUserAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        aip: int = 20,
        endorser_role: str = None,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="BEEDSUser",
            no_auto=no_auto,
            seed=None,
            aip=aip,
            endorser_role=endorser_role,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()


async def input_invitation(agent_container):
    agent_container.agent._connection_ready = asyncio.Future()
    async for details in prompt_loop("Invite details: "):
        b64_invite = None
        try:
            url = urlparse(details)
            query = url.query
            if query and "c_i=" in query:
                pos = query.index("c_i=") + 4
                b64_invite = query[pos:]
            elif query and "oob=" in query:
                pos = query.index("oob=") + 4
                b64_invite = query[pos:]
            else:
                b64_invite = details
        except ValueError:
            b64_invite = details

        if b64_invite:
            try:
                padlen = 4 - len(b64_invite) % 4
                if padlen <= 2:
                    b64_invite += "=" * padlen
                invite_json = base64.urlsafe_b64decode(b64_invite)
                details = invite_json.decode("utf-8")
            except binascii.Error:
                pass
            except UnicodeDecodeError:
                pass

        if details:
            try:
                details = json.loads(details)
                break
            except json.JSONDecodeError as e:
                log_msg("Invalid invitation:", str(e))

    with log_timer("Connect duration:"):
        connection = await agent_container.input_invitation(details, wait=True)


async def main(args):
    beeds_user_agent = await create_agent_with_args(args, ident="beeds_user")

    try:
        log_status(
            "#7 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {beeds_user_agent.wallet_type})"
                if beeds_user_agent.wallet_type
                else ""
            )
        )
        agent = BEEDSUserAgent(
            "beeds_user.agent",
            beeds_user_agent.start_port,
            beeds_user_agent.start_port + 1,
            genesis_data=beeds_user_agent.genesis_txns,
            no_auto=beeds_user_agent.no_auto,
            tails_server_base_url=beeds_user_agent.tails_server_base_url,
            timing=beeds_user_agent.show_timing,
            multitenant=beeds_user_agent.multitenant,
            mediation=beeds_user_agent.mediation,
            wallet_type=beeds_user_agent.wallet_type,
            aip=beeds_user_agent.aip,
            endorser_role=beeds_user_agent.endorser_role,
        )

        await beeds_user_agent.initialize(the_agent=agent)

        log_status("#9 Input boe.py invitation details")
        await input_invitation(beeds_user_agent)

        options = "    (3) Send Message\n" "    (4) Input New Invitation\n"
        if beeds_user_agent.endorser_role and beeds_user_agent.endorser_role == "author":
            options += "    (D) Set Endorser's DID\n"
        if beeds_user_agent.multitenant:
            options += "    (W) Create and/or Enable Wallet\n"
        options += "    (X) Exit?\n[3/4/{}X] ".format(
            "W/" if beeds_user_agent.multitenant else "",
        )
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option in "dD" and beeds_user_agent.endorser_role:
                endorser_did = await prompt("Enter Endorser's DID: ")
                await beeds_user_agent.agent.admin_POST(
                    f"/transactions/{beeds_user_agent.agent.connection_id}/set-endorser-info",
                    params={"endorser_did": endorser_did, "endorser_name": "endorser"},
                )

            elif option in "wW" and beeds_user_agent.multitenant:
                target_wallet_name = await prompt("Enter wallet name: ")
                include_subwallet_webhook = await prompt(
                    "(Y/N) Create sub-wallet webhook target: "
                )
                if include_subwallet_webhook.lower() == "y":
                    await beeds_user_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        webhook_port=beeds_user_agent.agent.get_new_webhook_port(),
                        mediator_agent=beeds_user_agent.mediator_agent,
                    )
                else:
                    await beeds_user_agent.agent.register_or_switch_wallet(
                        target_wallet_name,
                        mediator_agent=beeds_user_agent.mediator_agent,
                    )

            elif option == "3":
                msg = await prompt("Enter message: ")
                if msg:
                    await beeds_user_agent.agent.admin_POST(
                        f"/connections/{beeds_user_agent.agent.connection_id}/send-message",
                        {"content": msg},
                    )

            elif option == "4":
                # handle new invitation
                log_status("Input new invitation details")
                await input_invitation(beeds_user_agent)

        if beeds_user_agent.show_timing:
            timing = await beeds_user_agent.agent.fetch_timing()
            if timing:
                for line in beeds_user_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await beeds_user_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="beeds_user", port=8030)
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

            ptvsd.enable_attach(address = ('0.0.0.0', 5677))
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
                "beeds_user remote debugging to "
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

    check_requires(args)

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
