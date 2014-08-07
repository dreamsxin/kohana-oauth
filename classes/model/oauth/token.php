<?php defined('SYSPATH') or die('No direct access allowed.');
/**
 * @author     zhuzongxin dreamsxin@qq.com
 */
class Model_Oauth_Token extends ORM {
	
	protected $_belongs_to = array(
        'user' => array('model' => 'user', 'foreign_key' => 'user_id'),
        'consumer' => array('model' => 'oauth_consumer', 'foreign_key' => 'consumer_id'),
    );
	
	protected $_created_column = array("column" => "created", "format" => "Y-m-d H:i:s");
}
