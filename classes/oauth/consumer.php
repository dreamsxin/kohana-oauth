<?php defined('SYSPATH') or die('No direct script access.');

/**
 * @author     zhuzongxin dreamsxin@qq.com
 */
class OAuth_Consumer {

	private $oauth_consumer;

	public static function findByKey($key) {
		$consumer = null;
		$oauth_consumer = ORM::factory('oauth_consumer')->where('consumer_key', '=', $key)->find();
		if ($oauth_consumer->loaded() == 1) {
			$consumer = new OAuth_Consumer($oauth_consumer);
		}		
		return $consumer;
	}

	public function __construct($oauth_consumer) {
		if ($oauth_consumer && $oauth_consumer->loaded()) {
			$this->oauth_consumer = $oauth_consumer;
		} else {
			throw new Exception('oauth consumer not loaded');
		}
	}

	public static function create($key, $secret) {
		try {
			$oauth_consumer = ORM::factory('oauth_consumer');
			$oauth_consumer->consumer_key = $key;
			$oauth_consumer->consumer_secret = $secret;
			$oauth_consumer->active = 1;
			$oauth_consumer->save();
			$consumer = new Consumer($oauth_consumer);
			return $consumer;
		} catch (Exception $e) {
			throw new Exception('create consumer fail');
		}
	}

	public function isActive() {
		return $this->oauth_consumer->active;
	}

	public function getKey() {
		return $this->oauth_consumer->consumer_key;
	}

	public function getSecretKey() {
		return $this->oauth_consumer->consumer_secret;
	}

	public function getId() {
		return $this->oauth_consumer->id;
	}

	public function getType() {
		return (int)$this->oauth_consumer->consumer_type;
	}

	public function hasNonce($nonce, $timestamp) {
		$count = ORM::factory('oauth_consumer_nonce')
				->where('consumer_id', '=', $this->getId())
				->and_where('nonce', '=', $nonce)
				->and_where('timestamp', '=', $timestamp)->count_all();
		if ($count > 0) {
			return TRUE;
		} else {
			return FALSE;
		}
	}

	public function addNonce($nonce) {
		try {
			$oauth_consumer_nonce = ORM::factory('oauth_consumer_nonce');
			$oauth_consumer_nonce->consumer_id = $this->getId();
			$oauth_consumer_nonce->timestamp = time();
			$oauth_consumer_nonce->nonce = $nonce;
			$oauth_consumer_nonce->save();
		} catch (Exception $e) {
			throw new Exception('add nonce fail');
		}
	}

}
