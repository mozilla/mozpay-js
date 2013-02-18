var shouldBe = require('should');
var express = require('express');
var Gently = require('gently');
var jwt = require('jwt-simple');
var request = require('superagent');
var _ = require('underscore');

var config = {mozPayKey: 'my-app', mozPaySecret: 'THE SECRET',
              mozPayAudience: 'marketplace.firefox.com',
              mozPayRoutePrefix: '/mozpay'};
var payRequest = {pricePoint: 1,
                  id: 'my-product:1',
                  name: 'Unlock Level 10',
                  description: 'Lets you play Level 10! So fun!',
                  productData: '',
                  postbackURL: 'https://.../postback',
                  chargebackURL: 'https://.../chargeback'};
var incomingJWT = {iss: 'marketplace.firefox.com',
                   aud: config.mozPayKey,
                   // ...
                   request: payRequest};

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

  before(function() {
    pay.configure(config);
    this.request = payRequest;
    this.result = pay.request(this.request);

    this.decode = function _decode() {
      return jwt.decode(this.result, config.mozPaySecret);
    };

  });

  it('should encode a JWT with mozPaySecret', function() {
    this.decode();
  });

  it('should set iss to mozPayKey', function() {
    var res = this.decode();
    res.iss.should.equal(config.mozPayKey);
  });

  it('should set aud to mozPayAudience', function() {
    var res = this.decode();
    res.aud.should.equal(config.mozPayAudience);
  });

  it('should preserve request', function() {
    var res = this.decode();
    res.request.should.eql(this.request);
  });

  it('should require pre-configuration', function() {
    pay.configure(null);
    (function() { pay.request(this.request) }).should.throwError();
  });

});


describe('mozpay.verify', function() {

  before(function() {
    pay.configure(config);
  });

  it('should verify an incoming JWT', function() {
    pay.verify(jwt.encode(makeIncoming(), config.mozPaySecret));
  });

  it('should fail with the wrong signature', function() {
    (function() {
      pay.verify(jwt.encode(makeIncoming(), 'incorrect secret'));
    }).should.throwError('Signature verification failed');
  });

  it('should fail with a malformed JWT', function() {
    (function() {
      pay.verify(jwt.encode(makeIncoming(), config.mozPaySecret) + '.garbage');
    }).should.throwError('Not enough or too many segments');
  });

  it('should require pre-configuration', function() {
    pay.configure(null);
    (function() {
      pay.verify(jwt.encode(makeIncoming(), config.mozPaySecret));
    }).should.throwError();
  });

});


describe('mozpay.routes (config)', function() {

  before(function() {
    pay.configure(config);
    this.app = {
      post: function() {}
    };
    this.gently = new Gently();
  });

  after(function() {
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
    pay.configure({mozPayRoutePrefix: '/foo'});
    this.gently.expect(this.app, 'post', function(url) {
      shouldBe.equal(url, '/foo/postback');
    });
    pay.routes(this.app);
  });

  it('should clean the prefix', function() {
    pay.configure({mozPayRoutePrefix: '/foo/'});
    this.gently.expect(this.app, 'post', function(url) {
      shouldBe.equal(url, '/foo/postback');
    });
    pay.routes(this.app);
  });

  it('cannot have a null prefix', function() {
    pay.configure({mozPayRoutePrefix: null});
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
    this.postback({notice: jwt.encode(makeIncoming(), 'wrong secret')}, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must get a response object', function(done) {
    var notice = this.notice();
    delete notice.response;

    this.postback({notice: jwt.encode(notice, config.mozPaySecret)}, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must get a request object', function(done) {
    var notice = this.notice();
    delete notice.request;

    this.postback({notice: jwt.encode(notice, config.mozPaySecret)}, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must get a transactionID', function(done) {
    var notice = this.notice();
    delete notice.response.transactionID;

    this.postback({notice: jwt.encode(notice, config.mozPaySecret)}, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must respond with transaction ID', function(done) {
    var notice = this.notice();

    this.postback({notice: jwt.encode(notice, config.mozPaySecret)}, function(res) {
      res.status.should.equal(200);
      res.text.should.equal(notice.response.transactionID);
      done();
    });
  });

  it('must not get an expired JWT', function(done) {
    var notice = this.notice();
    notice.exp = pay.now() - 80;

    this.postback({notice: jwt.encode(notice, config.mozPaySecret)}, function(res) {
      res.status.should.equal(400);
      done();
    });
  });

  it('must not pre-process a JWT', function(done) {
    var notice = this.notice();
    notice.nbf = pay.now() + 360;  // not before...

    this.postback({notice: jwt.encode(notice, config.mozPaySecret)}, function(res) {
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

    this.postback({notice: jwt.encode(sentNotice, config.mozPaySecret)}, function(res) {
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
      .send({notice: jwt.encode(sentNotice, config.mozPaySecret)})
      .end(function(res) {
        res.status.should.equal(200);
      });
  });

});
