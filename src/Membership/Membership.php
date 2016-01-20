<?php

namespace Membership;

require_once(__DIR__ . '/models/user.php');
require_once(__DIR__ . '/models/session.php');
require_once(__DIR__ . '/models/verification-code.php');
require_once(__DIR__ . '/models/password-reset-code.php');

/**
 * Implements membership functions - sign-in/sign-up/sign-out etc.
 * @author Naveed Khan
 */
class Membership {
    
    /**
     * Tables
     */
    const TABLE_VERIFICATION_CODES = 'membership_verification_codes';

    /**
     * Error codes and other constants
     */
    const SUCCESS = 1000;
    const MIN_PSWD_LENGTH = 8;
    const ERROR_INVALID_EMAIL_OR_PSWD = 1001;
    const ERROR_EMAIL_NOT_VERIFIED = 1002;
    const ERROR_ACCOUNT_DISABLED = 1003;
    const ERROR_INVALID_EMAIL = 1004;
    const ERROR_ALREADY_EXISTS = 1005;
    const ERROR_PSWD_REQS_NOT_MET = 1006;
    const ERROR_INTERNAL_ERROR = 1007;
    const ERROR_DOES_NOT_EXIST = 1008;
    const ERROR_ALREADY_VERIFIED = 1009;
    const ERROR_FACEBOOK_ERROR = 1010;
    const ERROR_ACCOUNT_LOCKED = 1011;
    const ERROR_VERIFICATION_ERROR = 1012;

    /**
     * private fields - normally passed in through constructor
     */
    private $db = null;
    private $salt = null;
    private $support_email = null;
    private $support_name = null;
    private $app_name = null;
    private $debug_mode = false;
    private $logger = null;
    private $mailer = null;
    private $verify_url = null;
    private $reset_url = null;
    private $fb_app_id = null;
    private $fb_app_secret = null;
    private $max_failed_attempts = 3;
    
    /**
     * Constructor
     * @param params
     * @throws \Exception
     */
    public function __construct($params)
    {
        if(empty($params['db'])){
            throw new \Exception("Parameter `db` is required and must be a PDO instance.");
        }
        $this->db = $params['db'];

        if(empty($params['salt']) || strlen($params['salt']) < 8){
            throw new \Exception("Parameter `salt` is required and must be atleast 8 characters long");
        }
        $this->salt = $params['salt'];

        if(!empty($params['mailer'])) {
            $this->mailer = isset($params['mailer']) ? $params['mailer'] : null;
            $this->app_name = $params['app_name'];
            $this->support_email = $params['support_email'];
            $this->support_name = $params['support_name'];
        }

        if(isset($params['debug_mode'])){
            $this->debug_mode = $params['debug_mode'];
        }

        if(isset($params['verify_url']) ) {
            $this->verify_url = $params['verify_url'];
        }

        if(isset($params['reset_url'])){
            $this->reset_url = $params['reset_url'];
        }

        if(isset($params['logger'])){
            $this->logger =  $params['logger'];
        }

        if(isset($params['fb_app_id']) && isset($params['fb_app_secret'])){
            $this->fb_app_id = $params['fb_app_id'];
            $this->fb_app_secret =  $params['fb_app_secret'];
        }
        
        if(!empty($params['max_failed_attempts'])){
            $this->max_failed_attempts = $params['max_failed_attempts'];
        }
    }
    
    /**
     * login a user and create a session
     * @param string $email
     * @param string $pswd
     * @param int $expires
     * @return array
     */
    public function login($email, $pswd, $expires = 86400){
        
        if(empty($email)){
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if ( ! filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if(empty($pswd) or strlen($pswd) < self::MIN_PSWD_LENGTH){
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        $user = new User($this->db, $this->logger);
        if( ! $user->getByEmail($email)){
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }

        // non-local users are not allowed to login with user name and password
        if($user->source != User::SOURCE_LOCAL){
            return array(false, self::ERROR_DOES_NOT_EXIST);
        }

        if($user->status == User::STATUS_UNVERIFIED){
            return array(false, self::ERROR_EMAIL_NOT_VERIFIED);
        }

        if($user->status != User::STATUS_ENABLED){
            return array(false, self::ERROR_ACCOUNT_DISABLED);
        }

        if($user->failedAttempts >= $this->max_failed_attempts){
            return array(false, self::ERROR_ACCOUNT_LOCKED);
        }

        if( ! password_verify($pswd . $this->salt, $user->pswd)){
            $user->failedAttempts++;
            $user->save();
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if (password_needs_rehash($user->pswd, PASSWORD_BCRYPT)){
          $user->pswd = password_hash($pswd . $this->salt, PASSWORD_BCRYPT);
          $user->save(); 
        }

        $session = new Session($this->db, $this->logger);
        if( ! $session->getByUserId($user->id)){
            $session->userId = $user->id;
            $session->createdAt = time();
        }
        $session->token = bin2hex(openssl_random_pseudo_bytes(32));
        $session->expires = time() + $expires;
        if( ! $session->save()) {
            return array(false, self::ERROR_INTERNAL_ERROR);
        }
        
        return array(true, $session);
    }
    
    /**
     * Login using facebook
     * @param string $token
     * @param int $expires
     * @return array
     */
    public function facebook($token, $expires = 86400){

        if(empty($this->fb_app_id) or empty($this->fb_app_secret) or empty($token)){
            if($this->logger) $this->logger->addError("Facebook not properly configured");
            return array(false, self::ERROR_FACEBOOK_ERROR);
        }

        // get user info from facebook
        $fb = new \Facebook\Facebook(array(
            'app_id' => $this->fb_app_id,
            'app_secret' => $this->fb_app_secret,
            'default_graph_version' => 'v2.4',
            'default_access_token' => $token,
        ));

        try {
            $response = $fb->get('/me?fields=name,email');
            $me = $response->getGraphUser();
            $name = $me->getName();
            $email = $me->getField('email');
        }
        catch(\Facebook\Exceptions\FacebookResponseException $e) {
            if($this->logger) $this->logger->addError('Facebook Graph returned an error: ' . $e->getMessage());
            return array(false, self::ERROR_FACEBOOK_ERROR);
        }
        catch(\Facebook\Exceptions\FacebookSDKException $e) {
            if($this->logger) $this->logger->addError('Facebook SDK returned an error: ' . $e->getMessage());
            return array(false, self::ERROR_FACEBOOK_ERROR);
        }

        if(empty($email) or empty($name)){
            return array(false, self::ERROR_FACEBOOK_ERROR);
        }

        // check if a user with this email already exists
        $user = new User($this->db, $this->logger);
        if(!$user->getByEmail($email)){
          // create local user
          $user->name = $name;
          $user->email = $email;
          $user->pswd = "FACEBOOK";
          $user->type = User::TYPE_REGULAR_USER;
          $user->source = User::SOURCE_FACEBOOK;
          $user->status = User::STATUS_ENABLED;
          if(!$user->save()){
            return array(false, self::ERROR_INTERNAL_ERROR);
          }
        }

        // establish a session for this user
        $session = new Session($this->db, $this->logger);
        if(!$session->getByUserId($user->id)){
            $session->userId = $user->id;
            $session->createdAt = time();
        }
        $session->token = bin2hex(openssl_random_pseudo_bytes(32));
        $session->expires = time() + $expires;
        if(!$session->save()) {
            return array(false, self::ERROR_INTERNAL_ERROR);
        }

        return array(true, $session);
    }
    
    /**
     * logout a user and destroy the session
     * @param $sessionToken
     * @return array
     */
    public function logout($sessionToken){

        $session = new Session($this->db, $this->logger);
        if($session->getByToken($sessionToken, true)) {
            $session->expires = 0;
            $session->save();
        }

        return array(true, 0);
    }

    /**
     * finds a user from session token
     * @param $sessionToken
     * @return Session
     */
    public function getLoggedInUser($sessionToken){
        $session = new Session($this->db, $this->logger);
        if($session->getByToken($sessionToken, true))
        {
            $user = new User($this->db, $this->logger);
            if($user->getById($session->userId))
            {
                return $user;
            }
        }
        return null;
    }
    
    /**
     * register a new user
     * @param string $email
     * @param string $pswd
     * @param string $name
     * @param int $source
     * @param int $type
     * @return array
     */
    public function register($name, $email, $pswd, $phone, $source = User::SOURCE_LOCAL, $type = User::TYPE_REGULAR_USER){
        
        if(empty($email)){
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if(empty($pswd) or strlen($pswd) < self::MIN_PSWD_LENGTH){
            return array(false, self::ERROR_PSWD_REQS_NOT_MET);
        }
        
        $user = new User($this->db, $this->logger);
        if($user->getByEmail($email)){
            return array(false, self::ERROR_ALREADY_EXISTS);
        }
                
        $this->db->beginTransaction();
        
        $user->email = $email;
        $user->pswd = password_hash("{$pswd}{$this->salt}", PASSWORD_BCRYPT);
        $user->name = $name;
        $user->type = $type;
        $user->source = $source;
        $user->status = User::STATUS_UNVERIFIED;
        $user->phone = $phone;
        if(!$user->save()){
            $this->db->rollBack();
            return array(false, self::ERROR_INTERNAL_ERROR);
        }
        
        $vcode = new VerificationCode($this->db, $this->logger);
        $vcode->userId = $user->id;
        $vcode->code = bin2hex(openssl_random_pseudo_bytes(32));
        if(!$vcode->save()){
            $this->db->rollBack();
            return array(false, self::ERROR_INTERNAL_ERROR);
        }
        
        $this->db->commit();
        
        $this->sendVerificationEmail($user->id, $email, $vcode->code, $name);
        return array(true, 0);
    }
    
    /**
     * update a user info - type cannot be changed
     * @param int $id
     * @param string $name
     * @param string $email
     * @param string $pswd
     * @param string $phone
     * @return array
     */
    public function update($id, $name, $email, $pswd, $phone){
        
        if(empty($email)){
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if(!empty($pswd) and strlen($pswd) < self::MIN_PSWD_LENGTH){
            return array(false, self::ERROR_PSWD_REQS_NOT_MET);
        }
        
        $user = new User($this->db, $this->logger);
        if(!$user->getById($id) or  $user->source != User::SOURCE_LOCAL){
            return array(false, self::ERROR_DOES_NOT_EXIST);
        }
        
        if($user->email != $email){
            $test = new User($this->db, $this->logger);
            if($test->getByEmail($email)){
                return array(false, self::ERROR_ALREADY_EXISTS);
            }
            $user->email = $email;
            $user->status = User::STATUS_UNVERIFIED;
        }
                
        $user->name = $name;
        $user->phone = $phone;
        
        if(!empty($pswd) and $pswd != '********'){
            $user->pswd = password_hash("{$pswd}{$this->salt}", PASSWORD_BCRYPT);
        }
        
        $this->db->beginTransaction();
        
        if(!$user->save()){
            $this->db->rollBack();
            return array(false, self::ERROR_INTERNAL_ERROR);
        }
        
        if($user->status == USER::STATUS_UNVERIFIED){
            $vcode = new VerificationCode($this->db, $this->logger);
            $vcode->getByUserId($user->id);
            $vcode->userId = $user->id;
            $vcode->code = bin2hex(openssl_random_pseudo_bytes(32));
            $vcode->sendCount++;
            if(!$vcode->save()){
                $this->db->rollBack();
                return array(false, self::ERROR_INTERNAL_ERROR);
            }
            $this->sendVerificationEmail($user->id, $email, $vcode->code, $name);
        }
        
        $this->db->commit();
        
        return array(true, 0);
    }
    
    /**
     * get user details - works for local users onnly
     * @param int $id
     * @return array
     */
    public function details($id){
    
        if(empty($id)){
            return array(false, self::ERROR_DOES_NOT_EXIST);
        }
        
        $user = new User($this->db, $this->logger);
        if(!$user->getById($id) or $user->source != User::SOURCE_LOCAL){
            return array(false, self::ERROR_DOES_NOT_EXIST);
        }
            
        if($user->status == USER::STATUS_UNVERIFIED){
            return array(false, self::ERROR_EMAIL_NOT_VERIFIED);
        }
    
        // only return allowed details
        $ret = new \stdClass();
        foreach(array('id', 'name', 'email', 'phone') as $allowed){
            $ret->$allowed = $user->$allowed;
        }
        return array(true, $ret);
    }
    
    
    /**
     * forgot pswd - sends email
     * @param string $email
     * @return array
     */
    public function forgot($email){
        
        if (empty($email) or !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        $user = new User($this->db, $this->logger);
        if(!$user->getByEmail($email) or $user->source != User::SOURCE_LOCAL){
            return array(false, self::ERROR_DOES_NOT_EXIST);
        }

        $prk = new PasswordResetCode($this->db, $this->logger);
        if($prk->getByUserId($user->id)){
            if($prk->expires > time()){
                return array(false, self::ERROR_ALREADY_EXISTS);
            }
        }
        else {
            $prk->userId = $user->id;
        }
        $prk->code = bin2hex(openssl_random_pseudo_bytes(32));
        $prk->expires = time() + 10800;
        if(!$prk->save()){
            return array(false, self::ERROR_INTERNAL_ERROR);
        }
        
        // send email with pswd reset link
        $this->sendPswdResetCodeEmail($user->id, $email, $user->name, $prk->code);
        return array(true, 0);
    }
    
    /**
     * resend confirmation email 
     * @param string $email
     * @return int
     */
    public function resend($email)
    {
        if(empty($email))
        {
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) 
        {
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        $user = new User($this->db, $this->logger);
        if( ! $user->getByEmail($email))
        {
            return array(false, self::ERROR_DOES_NOT_EXIST);
        }
        
        if($user->status != User::STATUS_UNVERIFIED)
        {
          return self::ERROR_ALREADY_VERIFIED;
        }
        
        $vcode = new VerificationCode($this->db, $this->logger);
        if( ! $vcode->getByUserId($user->id)){
            return array(false, self::ERROR_DOES_NOT_EXIST);
        }
        
        // update the code and send it
        $vcode->code = bin2hex(openssl_random_pseudo_bytes(32));
        if($vcode->save()){
            return array(false, self::ERROR_INTERNAL_ERROR);
        }
        
        $this->sendVerificationEmail($user->id, $email, $vcode->code, $email);
        return array(true, $vcode->code);                
    }
    
    /**
     * confirm user account via code sent in email
     * @param int $userId
     * @param string $code
     * @return bool
     */
    public function confirm($userId, $code)
    {
        $vcode = new VerificationCode($this->db, $this->logger);
        if( ! $vcode->getByUserId($userId)){
            return array(false, self::ERROR_VERIFICATION_ERROR);
        }
        
        if( $vcode->code != $code){
            return array(false, self::ERROR_VERIFICATION_ERROR);
        }
        
        $user = new User($this->db, $this->logger);
        if($user->getById($userId)){
            $user->status = User::STATUS_ENABLED;
            $user->save();
        }
        
        return array(true, 0);
    }
    
    /**
     * Helper function to send verification email
     * @param int $userId
     * @param string $email
     * @param string $code
     * @param string $name
     * @param bool $new
     * @return bool
     */
    private function sendVerificationEmail($userId, $email, $code, $name, $new = true){

        if(empty($this->mailer)){
            return false;
        }

        $action = $new ? ' creating an ' : ' updating your ';
        $msg = "Dear {$name}\n\n"
             . "Thank you for {$action} account at {$this->app_name}.\n\n"
             . "Please confirm your email {$email} using the link below: \n\n"
             . "{$this->verify_url}/{$userId}/{$code}\n\n"
             . "--\nThanks\n{$this->support_name}\n{$this->support_email}\n";
        
        $this->mailer->addAddress($email, $name);
        $this->mailer->Subject = "{$this->app_name} - verify your email";
        $this->mailer->setFrom($this->support_email, $this->support_name);
        $this->mailer->Body = $msg;
        $this->mailer->isHTML(false);
        
        if (!$this->mailer->send()) {
            if($this->logger) $this->logger->addError("MAILER ERROR: " . $this->mailer->ErrorInfo);
            return false;
        }

        if($this->logger) $this->logger->addDebug("Message sent to {$email}!");
        return true;
    }
    
    /**
     * Helper function to send email to reset pswd using a link
     * @param int $userId
     * @param string $email
     * @param string $name
     * @param string $code
     * @return bool
     */
    private function sendPswdResetCodeEmail($userId, $email, $name, $code){

        if(empty($this->mailer)){
            return false;
        }

        $msg = "Dear " . $name . "\n\n"
             . "Please use the following link to reset your password for {$this->app_name}:\n\n"
             . "{$this->reset_url}/{$userId}/{$code}\n\n"
             . "Please note that this link is valid for a limited time.\n\n"
             . "--\nThanks\n{$this->support_name}\n{$this->support_email}\n";
        
        $this->mailer->addAddress($email, $name);
        $this->mailer->Subject = "{$this->app_name} - reset your password";
        $this->mailer->setFrom($this->support_email, $this->support_name);
        $this->mailer->Body = $msg;
        $this->mailer->isHTML(false);
        
        if (!$this->mailer->send()) {
            if($this->logger) $this->logger->addError("MAILER ERROR: " . $this->mailer->ErrorInfo);
            return false;
        }

        if($this->logger) $this->logger->addDebug("Message sent to {$email}!");
        return true;
    }
    
    /**
     * Delete a player by renaming its email so login will not work
     * but any exiting user data including foreign keys are preserved
     * @param int $userId
     * @return bool
     */
    public function delete($userId){

        $user = new User($this->db, $this->logger);
        if($user->getById($userId)) {
            $user->email = "D_" . bin2hex(openssl_random_pseudo_bytes(8)) . "_" . str_replace('@', '#', $user->email);
            $user->status = User::STATUS_DELETED;
            $user->save();
            return true;
        }
      
        return false;
    }
    
    
}
