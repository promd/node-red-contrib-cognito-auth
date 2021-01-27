# node-red-contrib-cognito-auth
this is a helper that uses the amazon-cognito-identity-js to create and maintain a valid JWT that can be used to authenticate further calls to the AWS platform (e.g. GraphQL).


## inputs
    msg.username
    msg.password
    

## output
    token on msg.payload (or the specified target attribute)

## dependencies
 - amazon-cognito-identity-js
 - jwt-decode