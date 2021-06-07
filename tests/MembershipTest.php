<?php

require_once __DIR__ . "/../vendor/autoload.php";
require_once __DIR__ . "/../src/Membership/Membership.php";

use Membership\Membership;
use PHPUnit\Framework\TestCase;

class MembershipTests extends TestCase
{
    private static $db = null;
    private static $membership = null;
    private static $testUserEmail = null;
    private static $testUserPswd = null;
    private static $sessionToken = null;

    /**
     * Setup required stuff for the test
     * @throws Exception
     */
    public static function setUpBeforeClass() :void
    {
        // Create a local database as follows:
        // CREATE USER 'travis'@'localhost';
        // GRANT USAGE ON *.* TO 'travis'@'localhost';
        // CREATE DATABASE IF NOT EXISTS `membership`;
        // GRANT ALL PRIVILEGES ON `membership`.* TO 'travis'@'localhost';
        self::$db = new \PDO(
            'mysql:host=localhost;dbname=membership;charset=utf8',
            'travis',
            null,
            array(
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_PERSISTENT => false
            )
        );
        
        self::$membership = new Membership(array(
               'db' => self::$db,
               'mailer' => null,
               'salt' => '!O5HA1069mf',
               'support_email' => null,
               'support_name' => null,
               'app_name' => 'Membership Test',
               'debug_mode' => true,
               'logger' => null,
               'max_failed_attempts' => 2
        ));
        
        $rand = uniqid();
        self::$testUserEmail = "{$rand}@{$rand}.com";
        self::$testUserPswd = $rand;
    }
    
    /**
     * Run a SELECT stmt
     * @param $sql
     * @param $params
     * @return mixed
     */
    private function executeQuery($sql, $params){
		try 
		{
			$stmt = self::$db->prepare($sql);
			foreach($params as $param){
				$stmt->bindValue($param[0], $param[1], $param[2]);
			}
			$stmt->execute();
			
			$rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
			if(count($rows) < 1){
				return false;
			}
		}
		catch(PDOException $pdoe){
			echo(__METHOD__ . "(): ERROR DURING PDO OPERATION" . json_encode(array('msg' => $pdoe->getMessage())));
			return false;
		}
        
		return $rows; 
    }
    
    /**
     * Test sign up
     */
    public function testRegister()
    {
        // test add new user
        list($success, $result) = self::$membership->register(
            'Test User',
            self::$testUserEmail,
            self::$testUserPswd,
            "123-456-7890"
        );
        $this->assertEquals(true, $success);
    }
    
    /**
     * Confirm a user using verifcation code
     */
    public function testConfirm()
    {
        // get verification code
		$sql = <<<EOF
			SELECT
				u.id,
				v.code
			FROM membership_users u, membership_verification_codes v
			WHERE u.id = v.user_id
			AND u.email = :email
EOF;
		$params = array(
		    array('email', self::$testUserEmail, \PDO::PARAM_STR)
		);
		$rows = $this->executeQuery($sql, $params);
		$this->assertGreaterThan(0, count($rows));
		
		// verify user
		list($success, $result) = self::$membership->confirm(
		    $rows[0]['id'],
		    $rows[0]['code']
		);
        
		$this->assertEquals(true, $success);
    }
    
    /**
     * Test sign in
     */
    public function testLogin()
    {
        list($success, $session) = self::$membership->login(
            self::$testUserEmail,
            self::$testUserPswd
        );
        $this->assertEquals(true, $success);
        $this->assertEquals(64, strlen($session->token));
        self::$sessionToken = $session->token;
   }
   
   /**
    * Logout
    */
   public function testLogout()
   {
       list($success, $result) = self::$membership->logout(self::$sessionToken);
       $this->assertEquals(true, $success);
   }
   
   /**
    * negative test for invalid user and password
    */
   public function testNegativeLogin()
   {
       // bad user
        list($success, $result) = self::$membership->login(
            "bad user",
            self::$testUserPswd
        );
        
        // bad password attempt 1
        $this->assertEquals(false, $success);
        list($success, $result) = self::$membership->login(
            self::$testUserEmail,
            "bad password"
        );
        $this->assertEquals(false, $success);
        
        // bad password attempt 2
        $this->assertEquals(false, $success);
        list($success, $result) = self::$membership->login(
            self::$testUserEmail,
            "bad password"
        );
        $this->assertEquals(false, $success);
        
        // bad password attempt 3
        $this->assertEquals(false, $success);
        list($success, $result) = self::$membership->login(
            self::$testUserEmail,
            "bad password"
        );
        $this->assertEquals(false, $success);
        
        // test failed attempts, should be 3 to make account locked
        $this->assertEquals(false, $success);
        list($success, $result) = self::$membership->login(
            self::$testUserEmail,
            self::$testUserPswd
        );
        $this->assertEquals(false, $success);
        $this->assertEquals(Membership::ERROR_ACCOUNT_LOCKED, $result);
        
   }
}

