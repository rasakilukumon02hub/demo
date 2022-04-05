// status codes
//  (see see https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-client-api-transport-v1.0-ps-20141208.html#uaf-status-codes)

export default {
  "1200": {
    message: "OK.",
    explanation: "Operation completed."
  },
  "1202": {
    message: "Accepted.",
    explanation: "Message accepted, but not completed at this time. The RP may need time to process the attestation, run risk scoring, etc. The server should not send an authenticationToken with a 1202 response."
  },
  "1400": {
    message: "Bad Request.",
    explanation: "The server did not understand the message."
  },
  "1401": {
    message: "Unauthorized.",
    explanation: "The userid must be authenticated to perform this operation, or this KeyID is not associated with this UserID."
  },
  "1403": {
    message: "Forbidden.",
    explanation: "The userid is not allowed to perform this operation. Client should not retry."
  },
  "1404": {
    message: "Not Found.",
    explanation: ""
  },
  "1408": {
    message: "Request Timeout.",
    explanation: ""
  },
  "1480": {
    message: "Unknown AAID.",
    explanation: "The server was unable to locate authoritative metadata for the AAID."
  },
  "1481": {
    message: "Unknown KeyID.",
    explanation: "The server was unable to locate a registration for the given UserID and KeyID combination. This error indicates that there is an invalid registration on the user's device. It is recommended that FIDO UAF Client deletes the key from local device when this error is received."
  },
  "1490": {
    message: "Channel Binding Refused.",
    explanation: "The server refused to service the request due to a missing or mismatched channel binding(s)."
  },
  "1491": {
    message: "Request Invalid.",
    explanation: "The server refused to service the request because the request message nonce was unknown, expired or the server has previously serviced a message with the same nonce and user ID."
  },
  "1492": {
    message: "Unacceptable Authenticator.",
    explanation: "The authenticator is not acceptable according to the server's policy, for example, because the capability registry used by the server reported different capabilities than client-side discovery."
  },
  "1493": {
    message: "Revoked Authenticator.",
    explanation: "The authenticator is considered revoked by the server."
  },
  "1494": {
    message: "Unacceptable Key.",
    explanation: "The key used is unacceptable. Perhaps it is on a list of known weak keys or uses insecure parameter choices."
  },
  "1495": {
    message: "Unacceptable Algorithm.",
    explanation: "The server believes the authenticator to be capable of using a stronger mutually-agreeable algorithm than was presented in the request."
  },
  "1496": {
    message: "Unacceptable Attestation.",
    explanation: "The attestation(s) provided were not accepted by the server."
  },
  "1497": {
    message: "Unacceptable Client Capabilities.",
    explanation: "The server was unable or unwilling to use required capabilities provided supplementally to the authenticator by the client software."
  },
  "1498": {
    message: "Unacceptable Content.",
    explanation: "There was a problem with the contents of the message and the server was unwilling or unable to process it."
  },
  "1500": {
    message: "Internal Server Error",
    explanation: ""
  }
};