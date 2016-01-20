<?php

namespace Membership;

require_once(dirname(__FILE__) . "/base-model.php");

class Session extends BaseModel {

    public $id = 0;
    public $userId = 0;
    public $token = null;
    public $createdAt = 0;
    public $expires = null;

    /**
     * constructor
     * @param \PDO $db
     * @param \Monolog\Logger $logger
     */
    public function __construct($db, $logger = null){
        parent::__construct($db, $logger);
    }

    /**
     * helper function to get session by parameter
     * @param array $params
     * @param bool $valid
     * @return bool
     */
    private function getByParams($params, $valid){
        $sql = <<<EOF
            SELECT
                id,
                user_id,
                token,
                created_at,
                expires
            FROM membership_sessions
            WHERE
EOF;
        try {
            $and = '';
            foreach($params as $param){
                $sql .= "{$and} {$param[0]} = :{$param[0]} ";
                $and = ' AND';
            }
            $this->logDebug($sql);
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
            if($valid and time() > $row['expires']){
                return false;
            }

            $this->id = $row['id'];
            $this->userId = $row['user_id'];
            $this->token = $row['token'];
            $this->createdAt = $row['created_at'];
            $this->expires = $row['expires'];
        }
        catch(\PDOException $pdoe){
            $this->logDebug(__METHOD__ . "(): ERROR DURING PDO OPERATION", array('msg' => $pdoe->getMessage()));
            return false;
        }

        return true;
    }

    /**
     * get a session by user id
     * @param int $userId
     * @param bool $valid
     * @return bool
     */
    public function getByUserId($userId, $valid = false){
        return $this->getByParams(
            array(
                array('user_id', $userId, \PDO::PARAM_STR)
            ),
            $valid
        );
    }

    /**
     * get a session by token
     * @param string $token
     * @param bool $valid
     * @return bool
     */
    public function getByToken($token, $valid = true){
        return $this->getByParams(
            array(
                array('token', $token, \PDO::PARAM_STR)
            ),
            $valid
        );
    }

    /**
     * save a session to db
     * @return bool
     */
    public function save(){
        if($this-> id > 0){
            $sql = <<<EOF
                UPDATE membership_sessions SET
                    token = :token,
                    expires = :expires
                WHERE user_id = :user_id
EOF;
            }
        else {
            $now = time();
            $sql = <<<EOF
                INSERT INTO membership_sessions (
                    user_id,
                    token,
                    created_at,
                    expires
                )
                VALUES (
                    :user_id,
                    :token,
                    {$now},
                    :expires
                )
EOF;
        }

        try {
            $this->logDebug($sql);
            $stmt = $this->db->prepare($sql);
            $params = array(
                array('user_id', $this->userId, \PDO::PARAM_INT),
                array('token', $this->token, \PDO::PARAM_STR),
                array('expires', $this->expires, \PDO::PARAM_INT)
            );
            $this->logDebug('PARAMS:', $params);
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
