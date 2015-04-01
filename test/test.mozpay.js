var shouldBe = require('should');
var express = require('express');
var Gently = require('gently');
var jwt = require('jsonwebtoken');
var request = require('superagent');
var _ = require('underscore');

var reqConfig = {
  mozPayKey: 'my-app',
  mozPaySecret: 'THE SECRET',
};
var config = _.defaults({}, reqConfig, {
  mozPayAudience: 'somewhere.firefox.com',
  mozPayType: 'mozilla-dev/payments/pay/v1',
  mozPayRoutePrefix: '/mozpay'
});
var payRequest = {
  pricePoint: 1,
  id: 'my-product:1',
  name: 'Unlock Level 10',
  description: 'Lets you play Level 10! So fun!',
  productData: '',
  postbackURL: 'https://.../postback',
  chargebackURL: 'https://.../chargeback'
};
var incomingJWT = {
  iss: 'marketplace.firefox.com',
  aud: config.mozPayKey,
  // ...
  request: payRequest
};

var pay = require('../lib/mozpay.js');


/*
 * Make an incoming JWT notice with valid iat/exp timestamps.
 * */
function makeIncoming(customIn) {
  var in_ = {};
  _.extend(in_, incomingJWT);
  if (customIn) {
    _.extend(in_, customIn);
  }
  if (!in_.iat) {
    in_.iat = pay.now();
  }
  if (!in_.exp) {
    in_.exp = pay.now() + 3600;  // in 1hr
  }
  return in_;
}


describe('mozpay.request', function() {

  beforeEach(function() {
    pay.configure(config);
    var self = this;
    this.request = payRequest;
    this.result = pay.request(this.request);

    this.verify = function(result) {
      result = result || self.result;
      return jwt.verify(result, config.mozPaySecret);
    };

  });

  it('should encode a JWT with mozPaySecret', function() {
    this.verify();
  });

  it('should set iss to mozPayKey', function() {
    var res = this.verify();
    res.iss.should.equal(config.mozPayKey);
  });

  it('should set aud to mozPayAudience', function() {
    var res = this.verify();
    res.aud.should.equal(config.mozPayAudience);
  });

  it('should set typ to mozPayType', function() {
    var res = this.verify();
    res.typ.should.equal(config.mozPayType);
  });

  it('should preserve request', function() {
    var res = this.verify();
    res.request.should.eql(this.request);
  });

  it('should require pre-configuration', function() {
    pay._resetConfig();
    (function() { pay.request(this.request) }).should.throwError();
  });

  it('should use defaults for optional config vars', function() {
    pay.configure({
      mozPayKey: config.mozPayKey,
      mozPaySecret: config.mozPaySecret,
    });
    var res = this.verify(pay.request(this.request));
    res.aud.should.equal('marketplace.firefox.com');
    res.iss.should.equal(config.mozPayKey);
  });

  it('should require non-optional config vars', function() {
    (function() { pay.configure({}) }).should.throwError();
  });

});


describe('mozpay.verify', function() {

  beforeEach(function() {
    pay.configure(config);
  });

  it('should verify an incoming JWT', function() {
    pay.verify(jwt.sign(makeIncoming(), config.mozPaySecret));
  });

  it('should fail with the wrong signature', function() {
    (function() {
      pay.verify(jwt.sign(makeIncoming(), 'incorrect secret'));
    }).should.throwError('invalid signature');
  });

  it('should fail with a malformed JWT', function() {
    (function() {
      pay.verify(jwt.sign(makeIncoming(), config.mozPaySecret) + '.garbage');
    }).should.throwError('jwt malformed');
  });

  it('should require pre-configuration', function() {
    pay._resetConfig();
    (function() {
      pay.verify(jwt.sign(makeIncoming(), config.mozPaySecret));
    }).should.throwError('configure() must be called before anything else.');
  });

  it('should fail for JWTs with a disallowed algorithm', function() {
    (function() {
      pay.verify(jwt.sign(makeIncoming(), config.mozPaySecret,
                          {algorithm: 'HS384'}));
    }).should.throwError('invalid signature');
  });

  it('should allow an override of supported algorithms', function() {
    pay.configure(_.defaults({supportedAlgorithms: ['HS384']}, config));
    pay.verify(jwt.sign(makeIncoming(), config.mozPaySecret,
                        {algorithm: 'HS384'}));
  });

});


describe('mozpay.routes (config)', function() {

  beforeEach(function() {
    pay.configure(config);
    this.app = {
      post: function() {}
    };
    this.gently = new Gently();
    this.configure = function(ob) {
      return pay.configure(_.defaults({}, reqConfig, ob));
    };
  });

  afterEach(function() {
    this.gently.verify();
  });

  it('should add a postback', function() {
    this.gently.expect(this.app, 'post', function(url) {
      shouldBe.equal(url, '/mozpay/postback');
    });
    pay.routes(this.app);
  });

  it('should add a chargeback', function() {
    var count = 1;
    this.gently.expect(this.app, 'post', 2, function(url) {
      if (count == 2)
        shouldBe.equal(url, '/mozpay/chargeback');
      count++;
    });
    pay.routes(this.app);
  });

  it('should use a prefix', function() {
    this.configure({mozPayRoutePrefix: '/foo'});
    this.gently.expect(this.app, 'post', function(url) {
      shouldBe.equal(url, '/foo/postback');
    });
    pay.routes(this.app);
  });

  it('should clean the prefix', function() {
    this.configure({mozPayRoutePrefix: '/foo/'});
    this.gently.expect(this.app, 'post', function(url) {
      shouldBe.equal(url, '/foo/postback');
    });
    pay.routes(this.app);
  });

  it('cannot have a null prefix', function() {
    this.configure({mozPayRoutePrefix: null});
    (function() {
      pay.routes(this.app);
    }).should.throwError();
  });

});


describe('mozpay.routes (handlers)', function() {

  before(function() {
    var self = this;
    pay.removeAllListeners();
    pay.configure(config);
    this.app = express.createServer();
    this.app.use(express.bodyParser());
    pay.routes(this.app);

    var port = 3001;
    this.app.listen(3001);

    this.url = function(path) {
      return 'http://localhost:' + port + config.mozPayRoutePrefix + path;
    }

    this.postback = function(data, onEnd) {
      request.post(self.url('/postback'))
        .send(data)
        .end(function(res) {
          onEnd(res);
        });
    };

    this.notice = function(customJWT) {
      return _.extend({}, makeIncoming(customJWT), {response: {transactionID: 'webpay-123'}});
    };
  });

  after(function() {
    this.app.close();
  });

  it('must get a notice parameter', function(done) {
    this.postback({}, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must get a valid JWT', function(done) {
    this.postback({notice: '<garbage>'}, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must get a JWT with correct signature', function(done) {
    this.postback({
      notice: jwt.sign(makeIncoming(), 'wrong secret'),
    }, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must get a response object', function(done) {
    var notice = this.notice();
    delete notice.response;

    this.postback({
      notice: jwt.sign(notice, config.mozPaySecret),
    }, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must get a request object', function(done) {
    var notice = this.notice();
    delete notice.request;

    this.postback({
      notice: jwt.sign(notice, config.mozPaySecret),
    }, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must get a transactionID', function(done) {
    var notice = this.notice();
    delete notice.response.transactionID;

    this.postback({
      notice: jwt.sign(notice, config.mozPaySecret),
    }, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must respond with transaction ID', function(done) {
    var notice = this.notice();

    this.postback({
      notice: jwt.sign(notice, config.mozPaySecret),
    }, function(res) {
      res.status.should.equal(200);
      res.text.should.equal(notice.response.transactionID);
      done();
    });
  });

  it('must not get an expired JWT', function(done) {
    var notice = this.notice();
    notice.exp = pay.now() - 80;

    this.postback({
      notice: jwt.sign(notice, config.mozPaySecret),
    }, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must not pre-process a JWT', function(done) {
    var notice = this.notice();
    notice.nbf = pay.now() + 360;  // not before...

    this.postback({
      notice: jwt.sign(notice, config.mozPaySecret),
    }, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must emit a postback event', function(done) {
    var sentNotice = this.notice();

    pay.on('postback', function(notice) {
      notice.should.eql(sentNotice);
      done();
    });

    this.postback({
      notice: jwt.sign(sentNotice, config.mozPaySecret),
    }, function(res) {
      res.status.should.equal(200);
    });
  });

  it('must emit a chargeback event', function(done) {
    var sentNotice = this.notice();

    pay.on('chargeback', function(notice) {
      notice.should.eql(sentNotice);
      done();
    });

    request.post(this.url('/chargeback'))
      .send({notice: jwt.sign(sentNotice, config.mozPaySecret)})
      .end(function(res) {
        res.status.should.equal(200);
      });
  });

});
