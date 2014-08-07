<?php defined('SYSPATH') or die('No direct script access.');

/**
 * @author     zhuzongxin dreamsxin@qq.com
 */
class OAuth_Provider {

	private $oauth;
	private $consumer;
	private $user_id;
	private $authentification_url;

	public static function createConsumer() {
		$key = sha1(OAuthProvider::generateToken(20, true));
		$secret = sha1(OAuthProvider::generateToken(20, true));
		return OAuth_Consumer::create($key, $secret);
	}

	public function __construct() {
		$config = Kohana::$config->load('oauth');
		$this->authentification_url = URL::base(TRUE).Arr::get($config, 'authentification_url');
		/* create our instance */
		$this->oauth = new OAuthProvider();

		/* setup check functions */
		$this->oauth->consumerHandler(array($this, 'checkConsumer'));
		$this->oauth->timestampNonceHandler(array($this, 'checkNonce'));
		$this->oauth->tokenHandler(array($this, 'checkToken'));
	}

	public function checkRequest() {	
		$this->oauth->checkOAuthRequest();
	}

	public function setRequestTokenQuery() {
		$this->oauth->isRequestTokenEndpoint(true);
		//$this->oauth->addRequiredParameter("oauth_callback");
	}

	public function generateRequestToken() {

		$token = sha1(OAuthProvider::generateToken(20, true));
		$token_secret = sha1(OAuthProvider::generateToken(20, true));

		$callback = $this->oauth->callback;

		OAuth_Token::createRequestToken($this->consumer, $token, $token_secret, $callback);	

		return array('authentification_url' => $this->authentification_url, 'oauth_token' => $token, 'oauth_token_secret' => $token_secret, 'oauth_callback_confirmed' => 'true');
	}

	public function generateAccesstoken() {

		$access_token = sha1(OAuthProvider::generateToken(20, true));
		$secret = sha1(OAuthProvider::generateToken(20, true));

		$token = OAuth_Token::findByToken($this->oauth->token);

		$token->changeToAccessToken($access_token, $secret);
		return array('oauth_token' => $access_token, 'oauth_token_secret' => $secret);
	}

	public static function generateVerifier() {
		$verifier = sha1(OAuthProvider::generateToken(20, true));
		return $verifier;
	}

	public function checkConsumer($provider) {
		$return = OAUTH_CONSUMER_KEY_UNKNOWN;

		$aConsumer = OAuth_Consumer::findByKey($provider->consumer_key);

		if (is_object($aConsumer)) {
			if (!$aConsumer->isActive()) {
				$return = OAUTH_CONSUMER_KEY_REFUSED;
			} else {
				$this->consumer = $aConsumer;
				$provider->consumer_secret = $this->consumer->getSecretKey();
				$return = OAUTH_OK;
			}
		}

		return $return;
	}

	public function checkToken($provider) {
		$token = OAuth_Token::findByToken($provider->token);

		if (is_null($token)) {
			return OAUTH_TOKEN_REJECTED;
		} elseif ($token->getType() == 1) {
			if ($token->getVerifier() != $provider->verifier) {
				return OAUTH_VERIFIER_INVALID;
			} else {
				$provider->token_secret = $token->getSecret();
				return OAUTH_OK;
			}
			
		} elseif ($token->getType() == 2) {
			if ($token->getExpires() > 0 && time() - strtotime($token->getCreated()) > (int)$token->getExpires()) {
				return OAUTH_TOKEN_EXPIRED;
			}
			$this->user_id = $token->getUserId();
			$provider->token_secret = $token->getSecret();
			return OAUTH_OK;
		}
	}

	public function checkNonce($provider) {
		if ($this->oauth->timestamp < time() - 5 * 60) {
			return OAUTH_BAD_TIMESTAMP;
		} elseif ($this->consumer->hasNonce($provider->nonce, $this->oauth->timestamp)) {
			return OAUTH_BAD_NONCE;
		} else {
			$this->consumer->addNonce($this->oauth->nonce);
			return OAUTH_OK;
		}
	}

	public function getUserId() {
		if ($this->user_id) {
			return $this->user_id;
		} else {
			throw new Exception("User not authentificated");
		}
	}

	public function getConsumer() {
		return $this->consumer;
	}

}
