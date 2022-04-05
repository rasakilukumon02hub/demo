function CIBAError(status, message, details) {
  this.status = status;
  this.message = message;
  this.details = details;
}

CIBAError.prototype = Object.create(Error.prototype);
CIBAError.prototype.constructor = CIBAError;
CIBAError.prototype.name = 'CIBAError';

function JWTError(status, message, details) {
  this.status = status;
  this.message = message;
  this.details = details;
}

JWTError.prototype = Object.create(Error.prototype);
JWTError.prototype.constructor = JWTError;
JWTError.prototype.name = 'JWTError';

function UserError(status, message, details) {
  this.status = status;
  this.message = message;
  this.details = details;
}

UserError.prototype = Object.create(Error.prototype);
UserError.prototype.constructor = UserError;
UserError.prototype.name = 'UserError';

function UAFError(message, code, details) {
  this.message = message;
  this.code = code;
  this.details = details;
  //  Error.captureStackTrace(null);
}

UAFError.prototype = Object.create(Error.prototype);
UAFError.prototype.constructor = UAFError;
UAFError.prototype.name = "UAFError";

function ClientError(status, message, details) {
  this.status = status;
  this.message = message;
  this.details = details;
}

ClientError.prototype = Object.create(Error.prototype);
ClientError.prototype.constructor = ClientError;
ClientError.prototype.name = 'ClientError';


module.exports = {
  CIBAError,
  JWTError,
  UserError,
  UAFError,
  ClientError
};