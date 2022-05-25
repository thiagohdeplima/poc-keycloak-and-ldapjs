const ldap   = require('ldapjs');
const server = ldap.createServer();

var util = require("./util");

var database = {
  "o=hoobox": {},

  "uid=thiago, o=hoobox": {
    "objectclass":["*"],
    "cn":["Thiago Henrique"],
    "sn":["de Paulo Lima"],
    "uid":["thiago"],
    "uuid":["1653182647253"],
    "mail": ["t@myemail.com"],
    "createTimestamp": [
      1653182647253
    ],
    "userpassword": ["123456"]
  },

  "uid=michelli, o=hoobox": {
    "objectclass":["*"],
    "cn":["Michelli Cristina"],
    "sn":["de Paulo Lima"],
    "uid":["michelli"],
    "uuid":["1653182647254"],
    "mail": ["m@myemail.com"],
    "createTimestamp": [
      1653182647254
    ],
    "userpassword": ["123456"]
  },
};

server.bind('cn=root', (req, res, next) => {
  util.audit(database, "binding user");

  if (req.dn.toString() !== 'cn=root' || req.credentials !== 'secret')
    return next(new ldap.InvalidCredentialsError());

  res.end();

  return next();
});

server.add(util.organization, util.authorize, (req, res, next) => {
  util.audit(database, "adding a new user");

  const dn = req.dn.toString();

  if (database[dn])
    return next(new ldap.EntryAlreadyExistsError(dn));

  database[dn] = {...req.toObject().attributes, uuid: Date.now().toString()}

  res.end();

  return next();
});

server.bind(util.organization, (req, res, next) => {
  util.audit(database, "a bind request")

  const dn = req.dn.toString();
  if (!database[dn])
    return next(new ldap.NoSuchObjectError(dn));

  if (!database[dn].userpassword)
    return next(new ldap.NoSuchAttributeError('userPassword'));

  if (database[dn].userpassword.indexOf(req.credentials) === -1)
    return next(new ldap.InvalidCredentialsError());

  res.end();

  return next();
});

server.compare(util.organization, util.authorize, (req, res, next) => {
  util.audit(database, "compare request")

  const dn = req.dn.toString();

  if (!database[dn])
    return next(new ldap.NoSuchObjectError(dn));

  const matches = false;
  const vals = database[dn][req.attribute];
  for (const value of vals) {
    if (value === req.value) {
      matches = true;
      break;
    }
  }

  res.end(matches);

  return next();
});

server.del(util.organization, util.authorize, (req, res, next) => {
  util.audit(database, "delete request");

  const dn = req.dn.toString();
  if (!database[dn])
    return next(new ldap.NoSuchObjectError(dn));

  delete database[dn];

  res.end();

  return next();
});

server.modify(util.organization, util.authorize, (req, res, next) => {
  util.audit(database, "modify request")

  const dn = req.dn.toString();
  const entry = database[dn];

  if (!req.changes.length) {
    return next(new ldap.ProtocolError('changes required'));
  }

  if (!database[dn]) {
    return next(new ldap.NoSuchObjectError(dn));
  }

  for (const change of req.changes) {
    mod = change.modification;
    switch (change.operation) {
    case 'replace':
      if (!entry[mod.type])
        return next(new ldap.NoSuchAttributeError(mod.type));

      if (!mod.vals || !mod.vals.length) {
        delete entry[mod.type];
      } else {
        entry[mod.type] = mod.vals;
      }

      break;

    case 'add':
      if (!entry[mod.type]) {
        entry[mod.type] = mod.vals;
      } else {
        for (const v of mod.vals) {
          if (entry[mod.type].indexOf(v) === -1)
            entry[mod.type].push(v);
        }
      }

      break;

    case 'delete':
      if (!entry[mod.type])
        return next(new ldap.NoSuchAttributeError(mod.type));

      delete entry[mod.type];

      break;
    }
  }

  res.end();

  return next();
});

server.search(util.organization, util.authorize, (req, res, next) => {
  util.audit(database, "search request")

  const dn = req.dn.toString();
  const keys = Object.keys(database);

  if (!database[dn])
    return next(new ldap.NoSuchObjectError(dn));

  let scopeCheck;

  switch (req.scope) {
  case 'base':
    if (req.filter.matches(database[dn])) {
      res.send({
        dn: dn,
        attributes: database[dn]
      });
    }

    res.end();

    return next();

  case 'one':
    scopeCheck = (k) => {
      if (req.dn.equals(k))
        return true;

      const parent = ldap.parseDN(k).parent();
      return (parent ? parent.equals(req.dn) : false);
    };
    break;

  case 'sub':
    scopeCheck = (k) => {
      return (req.dn.equals(k) || req.dn.parentOf(k));
    };

    break;
  }

  for (const key of keys) {
    if (!scopeCheck(key))
      return;

    if (req.filter.matches(database[key])) {
      res.send({
        dn: key,
        attributes: database[key]
      });
    }
  }

  res.end();

  return next();
});

server.listen(1389, () => {
  util.logger.info('LDAP server up at: %s', server.url);
});
