const AWSCognito = require('amazon-cognito-identity-js')
const jwtDecode = require('jwt-decode');

const validToken = token => {
    const now = Date.now().valueOf() / 1000

    try {
        const data = jwtDecode(token)
        if (typeof data.exp !== 'undefined' && data.exp < now) {
        return false
        }
        if (typeof data.nbf !== 'undefined' && data.nbf > now) {
        return false
        }
        return true
    } catch (e) {
        return false
    }
}

const session = ({ Username, Password, UserPoolId, ClientId, TokenType }) => new Promise((resolve, reject) => {
    new AWSCognito.CognitoUser({
      Username,
      Pool: new AWSCognito.CognitoUserPool({
        UserPoolId,
        ClientId,
      })
    }).authenticateUser(new AWSCognito.AuthenticationDetails({
      Username,
      Password
    }),
    {
      onSuccess: result => {
        TokenType === 'id' ? resolve(result.idToken.jwtToken): resolve(result.accessToken.jwtToken);
      },
      onFailure: error => {
        console.log(error);
        reject(error);
      }
    });
});

module.exports = function(RED) {
    function getJWToken(config) {
        RED.nodes.createNode(this,config);

        var Username    = this.credentials.username;
        var Password    = this.credentials.password;
        var node = this;
        this.status({fill:"red",shape:"ring",text:"unauthenticated"});

        node.on('input', function(msg) {
            var nodeContext = this.context();
            var token     = nodeContext.get("token");

            if (msg.hasOwnProperty("reset")) {
                token = "";
                delete msg.reset;
                nodeContext.set("token","");
            }

            if (msg.hasOwnProperty("username") || msg.hasOwnProperty("password")) {
                Username = msg.username;
                delete msg.username;
                Password = msg.password;
                delete msg.password;
            } 

            if (! validToken(token)) {
                // Compute a new token
                //node.warn("Invalid / expired Token:" + token);

                node.warn(config);
                const UserPoolId  = RED.util.evaluateNodeProperty(config.userpoolid,config.userpoolidType,node,msg);
                const ClientId    = RED.util.evaluateNodeProperty(config.clientid,config.clientidType,node,msg);
                const TokenType   = RED.util.evaluateNodeProperty(config.tokentype,config.tokentypeType,node,msg);

                try {
                    node.status({fill:"yellow",shape:"ring",text:"authenticating..."});
                    session({ Username, Password, UserPoolId, ClientId, TokenType })
                        .then((token) => { 
                            nodeContext.set("token",token);
                            node.status({fill:"green",shape:"ring",text:"authenticated"});
                            msg[config.target] = token;
                            node.send(msg);
                            })
                        .catch((error) => { node.error(error) }  )
                } catch(error){
                    node.error(error.message);
                    this.status({fill:"red",shape:"ring",text:"error"});
                }
  
            } else {
                //node.warn("Token OK");
                node.status({fill:"green",shape:"ring",text:"authenticated"});
                msg[config.target] = nodeContext.get("token");
                node.send(msg);
            }
        });
    }
    RED.nodes.registerType("cognito-auth",getJWToken,{
        credentials: {
            username: {type:"text"},
            password: {type:"password"}
        }
    });
}