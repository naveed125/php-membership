<?php

namespace Membership;

require_once(dirname(__FILE__) . '/base-model.php');

class VerificationCode extends BaseModel {
	
	public $id = 0;
	public $userId = 0;
	public $code = null;
	public $sendCount = 0;
	
	/**
	 * Constructor
	 * @param PDO $db
	 * @param Monolog $logger
	 */
	public function __construct($db, $logger = null){
		parent::__construct($db, $logger);
	}
	
	public function getByUserId($userId){
		$sql = <<<EOF
			SELECT
				id,
				user_id,
				code,
				send_count
			FROM membership_verification_codes
			WHERE user_id = :user_id
EOF;
		
		$params = array(
			array('user_id', $userId, \PDO::PARAM_INT),
		);
		
		try {
			$this->logDebug($sql, $params);
			$stmt = $this->db->prepare($sql);
			foreach($params as $param){
				$stmt->bindValue($param[0], $param[1], $param[2]);
			}
			$stmt->execute();
			$rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
			if(count($rows) < 1){
				return false;
			}
				
		}
		catch(\PDOException $pdoe){
			$this->logDebug(__METHOD__ . "(): ERROR DURING PDO OPERATION", array('msg' => $pdoe->getMessage()));
			return false;
		}
		
		$row = array_shift($rows);
		$this->id = $row['id'];
		$this->userId = $row['user_id'];
		$this->code = $row['code'];
		$this->sendCount = $row['send_count'];
		return true;
	}
	
	/**
	 * save the code to db
	 */
	public function save(){
		
		if($this->id > 0){
			$sql = <<<EOF
				UPDATE membership_verification_codes SET 
			    	user_id = :user_id,
					code = :code,
					send_count = :send_count
				WHERE id = :id
EOF;
			$params = array(
				array('id', $this->id, \PDO::PARAM_INT),
				array('code', $this->code, \PDO::PARAM_STR),
				array('user_id', $this->userId, \PDO::PARAM_INT),
				array('send_count', $this->sendCount, \PDO::PARAM_STR),
			);
		}
		else {
		
			$sql = <<<EOF
				INSERT INTO membership_verification_codes (
			    	user_id,
					code,
					send_count
				) VALUES (
					:user_id,
					:code,
					:send_count
				)
EOF;
			$params = array(
				array('user_id', $this->userId, \PDO::PARAM_INT),
				array('code', $this->code, \PDO::PARAM_STR),
				array('send_count', $this->sendCount, \PDO::PARAM_STR),
			);
		}
		
		try {
			$this->logDebug($sql, $params);
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