<?php defined('SYSPATH') or die('No direct script access.');

/**
 * @author     zhuzongxin dreamsxin@qq.com
 */
class OAuth_Token {

	protected $oauth_token;
	protected $consumer;

	/* static functions */
	public static function createRequestToken(OAuth_Consumer $consumer, $token, $tokensecret, $callback) {
		try {
			$oauth_token = ORM::factory('oauth_token');
			$oauth_token->type = 1;
			$oauth_token->consumer_id = $consumer->getId();
			$oauth_token->token = $token;
			$oauth_token->token_secret = $tokensecret;
			$oauth_token->callback_url = $callback;
			$oauth_token->user_id = 0;
			$oauth_token->verifier = '';
			$oauth_token->save();
		} catch (Exception $e) {
			throw new Exception('create request token fail:'.$e->getMessage());
		}
	}

	public static function findByToken($token) {
		$request_token = null;
		$oauth_token = ORM::factory('oauth_token')->where('token', '=', $token)->find();
		if ($oauth_token->loaded() == 1) {
			$request_token = new OAuth_Token($oauth_token);
		}
		return $request_token;
	}

	public static function findConsumerToken(OAuth_Consumer $consumer) {
		$config = Kohana::$config->load('oauth');
		$expir = (int)Arr::path($config, 'token.expir', 60);
		$oauth_token = ORM::factory('oauth_token')
				->where('consumer_id', '=', $consumer->getId())
				->and_where('type', '=', 1)
				->and_where(DB::expr('date_part(\'second\', \''.date('Y-m-d H:i:s').'\'-created) '), '<=', $expir)
				->find();
		return $oauth_token;
	}

	public function __construct($oauth_token) {
		if ($oauth_token && $oauth_token->loaded()) {
			$this->oauth_token = $oauth_token;
			$this->consumer = new OAuth_Consumer($oauth_token->consumer);
		} else {
			throw new Exception('oauth token not loaded');
		}
	}

	public function changeToAccessToken($token, $secret) {
		if ($this->isRequest()) {
		
			$oauth_token = $this->oauth_token;
			$oauth_token->type = 2;
			$oauth_token->verifier = '';
			$oauth_token->callback_url = '';
			$oauth_token->token = $token;
			$oauth_token->token_secret = $secret;
			$oauth_token->save();
			
			return true;
		} else {
			return false;
		}
	}

	/* some setters */

	public function setVerifier($verifier) {
		$oauth_token = $this->oauth_token;
		$oauth_token->verifier = $verifier;
		$oauth_token->save();
	}

	public function setUserId($user_id) {
		$oauth_token = $this->oauth_token;
		$oauth_token->user_id = $user_id;
		$oauth_token->save();
	}

	public function isRequest() {
		return (int)$this->oauth_token->type === 1;
	}

	public function isAccess() {
		return !$this->isRequest();
	}

	public function getCallback() {
		return $this->oauth_token->callback_url;
	}

	public function getConsumer() {
		return $this->oauth_token->consumer;
	}

	public function getVerifier() {
		return $this->oauth_token->verifier;
	}

	public function getType() {
		return $this->oauth_token->type;
	}

	public function getSecret() {
		return $this->oauth_token->token_secret;
	}

	public function getUserId() {
		return $this->oauth_token->user_id;
	}

	public function getExpires() {
		return $this->oauth_token->expires;
	}

	public function getCreated() {
		return $this->oauth_token->created;
	}

}
