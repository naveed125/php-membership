<?php

namespace Membership;

require_once(dirname(__FILE__) . '/models/user.php');
require_once(dirname(__FILE__) . '/models/session.php');
require_once(dirname(__FILE__) . '/models/verification-code.php');
require_once(dirname(__FILE__) . '/models/password-reset-code.php');

/**
 * Implements membership functions - sign-in/sign-up/sign-out etc.
 * @author Naveed Khan
 */
class Membership {
    
    /**
     * Tables
     */
    const TABLE_VERIFICATION_CODES = 'membership_verification_codes';
    const TABLE_SESSION = 'membership_session';
    
    /**
     * Error codes and other constants
     */
    const SUCCESS = 1000;
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
    
    const MIN_PSWD_LENGTH = 8;
    
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
    
    /**
     * Constructor
     * @param params 
     */
    public function __construct($params){
        $this->db = $params['db'];
        $this->salt = $params['salt'];
        $this->support_email = $params['support_email'];
        $this->support_name = $params['support_name'];
        $this->app_name = $params['app_name'];
        $this->debug_mode = $params['debug_mode'];
        $this->verify_url = isset($params['verify_url']) ? $params['verify_url'] : null;
        $this->reset_url = isset($params['reset_url']) ? $params['reset_url'] : null;
        $this->logger = isset($params['logger']) ? $params['logger'] : null;
        $this->mailer = isset($params['mailer']) ? $params['mailer'] : null;
        $this->fb_app_id = isset($params['fb_app_id']) ? $params['fb_app_id'] : null;
        $this->fb_app_secret = isset($params['fb_app_secret']) ? $params['fb_app_secret'] : null;
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
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        if(empty($pswd) or strlen($pswd) < self::MIN_PSWD_LENGTH){
            return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        $user = new User($this->db, $this->logger);
        if(!$user->getByEmail($email) or !password_verify($pswd . $this->salt, $user->pswd)){
          return array(false, self::ERROR_INVALID_EMAIL_OR_PSWD);
        }
        
        // non-local users are not allowed to login with user name and password
        if($user->source != User::SOURCE_LOCAL){
            return array(false, self::ERROR_DOES_NOT_EXIST);
        }
        
        if (password_needs_rehash($user->pswd, PASSWORD_BCRYPT)){
          $user->pswd = password_hash($pswd . $this->salt, PASSWORD_BCRYPT);
          $user->update(); 
        }
        
        if($user->status == User::STATUS_UNVERIFIED){
          return array(false, self::ERROR_EMAIL_NOT_VERIFIED);
        }
        
        if($user->status != User::STATUS_ENABLED){
          return array(false, self::ERROR_ACCOUNT_DISABLED);
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
        $fb = new \Facebook\Facebook([
            'app_id' => $this->fb_app_id,
            'app_secret' => $this->fb_app_secret,
            'default_graph_version' => 'v2.4',
            'default_access_token' => $token,
        ]);

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
     * @param $session
     * @return array
     */
    public function logout($session){
        if($this->app->session->id > 0) {
            $session->expires = 0;
            $session->save();
        }

        return array(true, 0);
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
    public function resend($email){

        if(empty($email)){
            return self::ERROR_INVALID_EMAIL_OR_PSWD;
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return self::ERROR_INVALID_EMAIL_OR_PSWD;
        }
        
        $query = $this->db->get_where(self::TABLE_USERS, array('email' => $email),    1, 0);
        if($query->num_rows() < 1){
            return self::ERROR_DOES_NOT_EXIST;
        }
        $user = array_shift($query->result());
        
        if($user->status != User::STATUS_UNVERIFIED){
          return self::ERROR_ALREADY_VERIFIED;
        }
        
        $query = $this->db->get_where(self::TABLE_VERIFICATION_CODES, array('user_id' => $user->id), 1, 0);
        if($query->num_rows() < 1){
            return self::ERROR_INTERNAL_ERROR;
        }
        
        $verification = array_shift($query->result());
        $verification->send_count++;
        $this->db->update(self::TABLE_VERIFICATION_CODES, $verification, array('id' => $verification->id));
        
        $this->sendVerificationEmail($user->id, $email, $verification->code, $user->name);
        return self::SUCCESS;
    }
    
    /**
     * confirm code sent in email
     * @param int $userId
     * @param string $code
     * @return bool
     */
    public function confirm($userId, $code)
    {
        // TODO FIX THIS
        return array(false, "not implemented");

//        $query = $this->db->get_where(self::TABLE_USERS, array('id' => $userId), 1, 0);
//        if ($query->num_rows() < 1) {
//            return array(false, 'Invalid verification attempt.');
//        }
//        $user = array_shift($query->result());
//
//        if ($user->status != User::STATUS_UNVERIFIED) {
//            return array(false, 'Your email is already verified, please <a href="' . base_url('/user/signin') . '">Sign in</a>.');
//        }
//
//        $params = array(
//            'user_id' => $userId,
//            'code' => $code
//        );
//        $query = $this->db->get_where(self::TABLE_VERIFICATION_CODES, $params, 1, 0);
//        if ($query->num_rows() < 1) {
//            return array(false, 'We are unable to confirm verification code at the moment. Please contact <a href="mailto:{$this->support_email}">{$this->support_email}</a>.');
//        }
//
//        $user->status = User::STATUS_ENABLED;
//        $this->db->update(self::TABLE_USERS, $user, array('id' => $userId));
//
//        return array(true, 'Success! Thankyou for verifying your email with us. You may <a href="' . base_url('/user/signin') . '">Sign In</a> to access your account.');
    }
    
    /**
     * Helper function to send verification email
     * @param int $userId
     * @param string $email
     * @param string $code
     * @param string $name
     * @return bool
     */
    private function sendVerificationEmail($userId, $email, $code, $name, $new = true){

        if(empty($this->mailer)){
            return false;
        }

        $action = $new ? ' creating an ' : ' updating your ';
        $msg = "Dear {$name}\n\n"
             . "Thank you for {$action} your account at {$this->app_name}.\n\n"
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
