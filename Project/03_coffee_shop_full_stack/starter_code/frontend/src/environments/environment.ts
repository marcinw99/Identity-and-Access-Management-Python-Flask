export const environment = {
    production: false,
    apiServerUrl: 'http://127.0.0.1:5000', // the running FLASK api server url
    auth0: {
        url: 'huffer.eu', // the auth0 domain prefix
        audience: 'drinks-service', // the audience set for the auth0 app
        clientId: '7l13QCRVDue1BlTac0R6yqwWOCw0ZTQu', // the client id generated for the auth0 app
        callbackURL: 'http://localhost:8100', // the base url of the running ionic application.
    }
};
