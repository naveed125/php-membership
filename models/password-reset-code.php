<?php

namespace Membership;

require_once(dirname(__FILE__) . "/base-model.php");

class PasswordResetCode extends BaseModel {
	
	public $id = 0;
	public $userId = 0;
	public $code = null;
	public $createdAt = 0;
	public $expires = 0;
	
	/**
	 * constructor
	 * @param PDO $db
	 * @param Monolog $logger
	 */
	public function __construct($db, $logger = null){
		parent::__construct($db, $logger);
	}
	
	/**
	 * get a code from db if one exists
	 * @param int $userId
	 */
	public function getByUserId($userId){
		$sql = <<<EOF
			SELECT
				id,
				user_id,
				code,
		    	created_at,
				expires
			FROM membership_pswd_reset_codes
		    WHERE user_id = :user_id
EOF;
		
		$params = array(
			array('user_id', $userId, \PDO::PARAM_INT)
		);
		
		$this->logDebug($sql, $params);
		
		try {
			$stmt = $this->db->prepare($sql);
			foreach($params as $param){
				$stmt->bindValue($param[0], $param[1], $param[2]);
			}
			$stmt->execute();
		
			$rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
			if(count($rows) < 1){
				return false;
			}
				
			$row = array_shift($rows);
			$this->id = $row['id'];
			$this->userId = $row['user_id'];
			$this->code = $row['code'];
			$this->createdAt = $row['created_at'];
			$this->expires = $row['expires'];
		}
		catch(\PDOException $pdoe){
			$this->logDebug(__METHOD__ . "(): ERROR DURING PDO OPERATION", array('msg' => $pdoe->getMessage()));
			return false;
		}
		
		return true;
	}
	
	public function save(){
		
		if($this-> id > 0){
			$sql = <<<EOF
				UPDATE membership_pswd_reset_codes SET
					code = :code,
					expires = :expires
				WHERE user_id = :user_id 
EOF;
			}
		else {
			$now = time();
			$sql = <<<EOF
				INSERT INTO membership_pswd_reset_codes (
					user_id,
					code,
			    	created_at,
					expires
				)
				VALUES (
					:user_id,
					:code,
					{$now},
					:expires
				)
EOF;
		}
		
		$params = array(
			array('user_id', $this->userId, \PDO::PARAM_INT),
			array('code', $this->code, \PDO::PARAM_STR),
			array('expires', $this->expires, \PDO::PARAM_INT)
		);
		$this->logDebug($sql, $params);
		
		try {
			$stmt = $this->db->prepare($sql);
			foreach($params as $param){
				$stmt->bindValue($param[0], $param[1], $param[2]);
			}
			$stmt->execute();
			
			if($this->id <= 0){
				$this->id = $this->db->lastInsertId();
			}
		}
		catch(\PDOException $pdoe){
			$this->logDebug(__METHOD__ . "(): ERROR DURING PDO OPERATION", array('msg' => $pdoe->getMessage()));
			return false;
		}

		return true;
	}
	
}
	