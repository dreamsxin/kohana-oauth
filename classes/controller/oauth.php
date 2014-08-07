<?php defined('SYSPATH') or die('No direct script access.');
/**
 * @author zhuzx dreamsxin@qq.com
 */
class Controller_OAuth extends Controller {
	
	public function action_index() {
		$result = array('status' => '400');
		$this->sendQuery($result);
	}
	
	// 获取未授权的Request Token 
	public function action_request() {
		$result = array('status' => '400');
		$provider = new OAuth_Provider();
		$provider->setRequestTokenQuery();
		try {
			$provider->checkRequest();
			$token = $provider->generateRequestToken();

			$result['status'] = 200;
			$result = Arr::merge($result, $token);
		} catch (Exception $e) {
			$result['code'] = $e->getCode();
			$result['message'] = $e->getMessage();
		}
		$this->sendQuery($result);
	}
	
	// 获取用户授权的Request Token 
	public function action_authorize() {
		$result = array('status' => '400');
		try {
			
			$oauth_token = Arr::get($_REQUEST, 'oauth_token');
			if (!$oauth_token) {
				throw new Exception('缺少 oauth_token');
			}
			$request_token = OAuth_Token::findByToken($oauth_token);

			if(!is_object($request_token) || !$request_token->isRequest()){
				throw new Exception('oauth_token 错误');
			}
			$username = Arr::get($_REQUEST, 'username');
			$password = Arr::get($_REQUEST, 'password');
			
			if (Auth::instance()->login($username, $password) !== TRUE) {
				throw new Exception('用户名或密码错误');
			}
			$request_token->setVerifier(OAuth_Provider::generateVerifier());
			$request_token->setUserId(Auth::instance()->instance()->get_user()->id);
			
			$result['status'] = 200;
			$result['message'] = '授权成功';
			$result['callback'] = $request_token->getCallback();
			$result['oauth_token'] = $oauth_token;
			$result['oauth_verifier'] = $request_token->getVerifier();
		} catch (Exception $e) {
			$result['message'] = $e->getMessage();
		}
		$this->sendQuery($result);
	}
	
	// 使用授权后的Request Token换取Access Toke
	public function action_access() {
		$filename = DOCROOT . 'data/access.txt';
		file_put_contents($filename, date('Y-m-d H:i:s') . 'header ' . json_encode($this->request->headers()) . PHP_EOL, FILE_APPEND);
		file_put_contents($filename, date('Y-m-d H:i:s') . '$_REQUEST ' . json_encode($_REQUEST) . PHP_EOL, FILE_APPEND);
		file_put_contents($filename, date('Y-m-d H:i:s') . 'METHOD ' . $this->request->method() . PHP_EOL, FILE_APPEND);
			
		$result = array('status' => '400');
		// xauth
		$x_auth_mode = Arr::get($_REQUEST, 'x_auth_mode');
		if ($x_auth_mode == 'client_auth') {
			$username = Arr::get($_REQUEST, 'x_auth_username');
			$password = Arr::get($_REQUEST, 'x_auth_password');
			if (Auth::instance()->login($username, $password) !== TRUE) {
				throw new Exception('用户名或密码错误');
			}
			
			$userid = Auth::instance()->instance()->get_user()->id;
			
			try {				
				// 生成request token
				$provider = new OAuth_Provider();
				$provider->setRequestTokenQuery();
				$provider->checkRequest();
				$consumer = $provider->getConsumer();
				if ($consumer->getType() !== 1) {
					throw new Exception('请申请XAuth认证');
				}

				$oauth_token = ORM::factory('oauth_token')
						->and_where('consumer_id', '=', $consumer->getId())
						->and_where('user_id', '=', $userid)
						->and_where('type', '=', 2)
						->find();
				
				if ($oauth_token->loaded()) {
					$token = $oauth_token->token;
					$secret = $oauth_token->token_secret;
				} else {
					$token = sha1(OAuthProvider::generateToken(20, true));
					$secret = sha1(OAuthProvider::generateToken(20, true));
					$oauth_token = ORM::factory('oauth_token');
					$oauth_token->type = 2;
					$oauth_token->consumer_id = $consumer->getId();
					$oauth_token->token = $token;
					$oauth_token->token_secret = $secret;
					$oauth_token->callback_url = '';
					$oauth_token->user_id = $userid;
					$oauth_token->verifier = '';
					$oauth_token->save();
				}
				$result = array('status' => 200, 'oauth_token' => $token, 'oauth_token_secret' => $secret);
			} catch (Exception $e) {
				$result['code'] = $e->getCode();
				$result['message'] = $e->getMessage();
			}
			$this->sendQuery($result);
		} else {
			$provider = new OAuth_Provider();
			try {
				$provider->checkRequest();
				$token = $provider->generateAccessToken();
				$result['status'] = 200;
				$result = Arr::merge($result, $token);
			} catch (Exception $e) {
				$result['code'] = $e->getCode();
				$result['message'] = $e->getMessage();
			}

			$this->sendQuery($result);
		}
	}
	
	public function action_create() {
		exit;
		$result = array('status' => '400');
		try {
			$consumer = Provider::createConsumer();
			$result['status'] = 200;
			$result['key'] = $consumer->getKey();
			$result['secret'] = $consumer->getSecret();
		} catch (Exception $e) {
			$result['message'] = $e->getMessage();
		}
		
		$this->sendQuery($result);
	}
	
	public function action_test() {	
		$filename = DOCROOT . 'data/test.txt';
		file_put_contents($filename, date('Y-m-d H:i:s') . 'header ' . json_encode($this->request->headers()) . PHP_EOL, FILE_APPEND);
		file_put_contents($filename, date('Y-m-d H:i:s') . '$_REQUEST ' . json_encode($_REQUEST) . PHP_EOL, FILE_APPEND); 
		file_put_contents($filename, date('Y-m-d H:i:s') . 'body ' . $this->request->body() . PHP_EOL, FILE_APPEND); 
		file_put_contents($filename, date('Y-m-d H:i:s') . 'METHOD ' . $this->request->method() . PHP_EOL, FILE_APPEND);
			
		$result = array('status' => '400');
		$provider = new OAuth_Provider();
		try {
			$provider->checkRequest();
			$userid = $provider->getUserId();
			$result['status'] = 200;
			$result['message'] = '';
			$result['userid'] = $userid;
		} catch (Exception $e) {
			$result['message'] = $e->getMessage();
		}
		
		$this->sendQuery($result);
	}

	// 输出JSON
	public function sendQuery($result, $header = TRUE) {
		if ($header) {
			$this->response->headers('Content-Type', 'application/json');
		}
		$this->sendBody(json_encode($result));
		$body = is_array($result) ? http_build_query($result) : $result;
		$this->sendBody($body);
	}

	// 输出
	public function sendBody($body) {
		$this->response->body($body);
		echo $this->response->send_headers()->body();
		exit;
	}	
}

