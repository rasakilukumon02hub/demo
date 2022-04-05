function getAuthenticationRequestTemplate() {
  return {
    uafRequest: [
      {
        header: {
          upv: {
            major: 1,
            minor: 1
          },
          op: 'Auth'
        }
      }
    ]
  };
}


module.exports = {
  getAuthenticationRequestTemplate: getAuthenticationRequestTemplate
};
