<?php

namespace Membership;

require_once(dirname(__FILE__) . '/base-model.php');

class User extends BaseModel {
	
	/**
	 * fields
	 */
	public $id = 0;
	public $email = null;
	public $name = null;
	public $pswd = null;
	public $status = null;
	public $type = null;
	public $source = null;
	public $phone = null;
	public $failedAttempts = 0;
	
	/**
	 * Sources for user id
	 */
	const SOURCE_UNKNOWN  =  0;   // unknown/invalid
	const SOURCE_LOCAL    =  100; // created locally in our system
	const SOURCE_FACEBOOK =  200; // facebook
	const SOURCE_TWITTER  =  300; // twitter
	const SOURCE_GOOGLE   =  400; // google
	
	/**
	 * User statuses
	 */
	const STATUS_DISABLED   =  0;
	const STATUS_ENABLED    =  100;
	const STATUS_UNVERIFIED =  200;
	const STATUS_LOCKED     =  300;
	const STATUS_DELETED    =  400;
	
	/**
	 * User types - used in user profile and may be application dependent
	 */
	const TYPE_UNKNOWN = 0;
	const TYPE_SUPER_ADMIN = 100;
	const TYPE_AREA_MANGER = 200;
	const TYPE_REGULAR_USER = 300;
	
	/**
	 * Constructor
	 * @param \PDO $db
	 * @param \Monolog $logger
	 */
	public function __construct($db, $logger = null){
		parent::__construct($db, $logger);
	}
	
	/**
	 * get user by email
	 * @param string $email
	 * @return array
	 */
	public function getByEmail($email){
		return $this->getByParams(
			array(
				array('email', $email, \PDO::PARAM_STR)
			)
		);
	}
	
	/**
	 * get user by id
	 * @param string $id
	 * @return bool
	 */
	public function getById($id){
		return $this->getByParams(
			array(
				array('id', $id, \PDO::PARAM_STR)
			)
		);
	}
	
	/**
	 * finds a user by params
	 * @param array $params
	 * @return bool
	 */
	private function getByParams($params){
		$sql = <<<EOF
			SELECT
				id,
				created_at,
				email,
		    	name,
				pswd,
				status,
				user_type,
				source,
				phone,
		        failed_attempts
			FROM membership_users
			WHERE id > 0
EOF;
		
		foreach($params as $param){
			$sql .= " AND {$param[0]} = :{$param[0]}";
		}
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
		}
		catch(\PDOException $pdoe){
			$this->logDebug(__METHOD__ . "(): ERROR DURING PDO OPERATION", array('msg' => $pdoe->getMessage()));
			return false;
		}
		
		$row = array_shift($rows);
		$this->id = $row['id'];
		$this->name = $row['name'];
		$this->email = $row['email'];
		$this->pswd = $row['pswd'];
		$this->status = $row['status'];
		$this->type = $row['user_type'];
		$this->source = $row['source'];
		$this->phone = $row['phone'];
		$this->failedAttempts = $row['failed_attempts'];
		return true;
	}
	
	/**
	 * Save a user to database
	 */
	public function save(){
		
		if($this->id > 0){
			// existing user - perform update
			$sql = <<<EOF
				UPDATE membership_users SET 
			    	name = :name,
					email = :email,
					pswd = :pswd,
					status = :status,
					phone = :phone,
			        failed_attempts = :failed_attempts
				WHERE id = :id
EOF;

			$params = array(
				array('id', $this->id, \PDO::PARAM_INT),
				array('name', $this->name, \PDO::PARAM_STR),
				array('email', $this->email, \PDO::PARAM_STR),
				array('pswd', $this->pswd, \PDO::PARAM_STR),
				array('status', $this->status, \PDO::PARAM_INT),
				array('phone', $this->phone, \PDO::PARAM_STR),
			    array('failed_attempts', $this->failedAttempts, \PDO::PARAM_STR),
			);
		}
		else {
			// new user - perform insert
			$sql = <<<EOF
				INSERT INTO membership_users (
					created_at,
			    	name,
					email,
					pswd,
					status,
					user_type,
					source,
					phone
				) VALUES (
					:created_at,
					:name,
					:email,
					:pswd,
					:status,
					:user_type,
					:source,
					:phone
				)
EOF;
		
			$params = array(
				array('created_at', time(), \PDO::PARAM_INT),
				array('name', $this->name, \PDO::PARAM_STR),
				array('email', $this->email, \PDO::PARAM_STR),
				array('pswd', $this->pswd, \PDO::PARAM_STR),
				array('status', $this->status, \PDO::PARAM_INT),
				array('user_type', $this->type, \PDO::PARAM_INT),
				array('source', $this->source, \PDO::PARAM_INT),
				array('phone', $this->phone, \PDO::PARAM_STR),
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