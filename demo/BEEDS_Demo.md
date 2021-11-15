
## Prerequisites for BEEDS PoC demonstration
- VON-network repo: https://github.com/bcgov/von-network 
- Docker installed / Access to Docker Play 
- Python v3


## Steps to run demonstration

1. Have VON-network running locally (follow steps in: ). Able to access http://localhost:9000/ when running 
2. In a new terminal window, from aries-cloudagent-pythin/demo run './run_demo boe' 
3. In another new terminal window, from aries-cloudagent-pythin/demo run './run_demo beed_user' 
4. Follow the command-line instructions, including copying the 'Invitation Data' (please see example below) from BoE agent and enter into the BEEDSuser agent terminal to estbalish a connections:

            Invitation Data:
            {"@type": "https://didcomm.org/out-of-band/1.0/invitation", "@id": "9109c998-f26a-4dbd-8200-33c805e6af03", "handshake_protocols": ["https://didcomm.org/didexchange/1.0"], "label": "boe.agent", "services": [{"id": "#inline", "type": "did-communication", "recipientKeys": ["did:key:z6MkvRNQn9mAUq5eKYKox2LQCZ6KVWDNnW77AsjT9Bnfmae1"], "serviceEndpoint": "http://172.17.0.1:8020"}]}




## Revocation functionality

To view how the credential can also be revoked (using accumulators), the following command can be run from aries-cloudagent-pythin/demo:'./run_demo boe --revocation' 

Please note that the --revocation argument will only function as expected after the './run_demo boe' has alreday been run first in each VON-network session.  

