const ldap = require('ldapjs');

const organization = 'o=hoobox';

const bunyan = require('bunyan');
const logger = bunyan.createLogger({name: "ldap-poc"});


function authorize(req, _res, next) {
  logger.info({dn: req.dn, req: req}, "authorizing request");

  const isSearch = (req instanceof ldap.SearchRequest);

  if (!req.connection.ldap.bindDN.equals('cn=root') && !isSearch) {
    return next(new ldap.InsufficientAccessRightsError());
  }
  
  return next();
}

function audit(database, msg) {
  try {
    logger.info({database: database}, msg);
  } catch(e) {
    logger.info(`Error: ${e}`)
  }
}

module.exports = {
  organization, authorize, audit, logger
}