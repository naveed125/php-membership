-- ----------------------------------------------------------------------
-- User table
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS membership_users;
CREATE TABLE membership_users (

    id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    
    -- Valid sources
    -- 0: local - created in our system
    -- 100: facebook
    -- 200: twitter
    -- 300: google
    source SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    
    -- user_id can email or a token from another service like facebook
    email VARCHAR(128) NOT NULL UNIQUE,
    
    -- name of the user (we dont have first and last)
    name VARCHAR(256) NOT NULL,
    
    -- phone of the user - can be null
    phone VARCHAR(32),    
    
    -- user_type can be used internally, e.g:
    -- 0: unknown
    -- 100: super admin
    -- 200: area manager
    -- 300: regular user/customer
    user_type SMALLINT UNSIGNED NOT NULL,

    -- hashed password
    pswd VARCHAR(256) NOT NULL,

    created_at INT UNSIGNED NOT NULL,
    
    -- Valid status:
    -- 0: disabled
    -- 100: enabled
    -- 200: unverified
    -- 300: locked
    status SMALLINT UNSIGNED NOT NULL,

    -- number of times wrong pswd was supplied
    -- resets to 0 after successful login
    failed_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0    
)
ENGINE=InnoDB
DEFAULT CHARACTER SET utf8;

-- ----------------------------------------------------------------------
-- Profile table
-- This is an extension to the user table to keep the user table columns
-- to a miminum and may contain application specific data
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS membership_profiles;
CREATE TABLE membership_profiles (

  id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL REFERENCES membership_users(id)
)
ENGINE=InnoDB
DEFAULT CHARACTER SET utf8;

-- ----------------------------------------------------------------------
-- Verification codes
-- used for email verifications
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS membership_verification_codes;
CREATE TABLE membership_verification_codes (
    id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNSIGNED NOT NULL UNIQUE REFERENCES membership_users(id),
    code VARCHAR(64) NOT NULL,
    send_count SMALLINT UNSIGNED NOT NULL DEFAULT 1
)
ENGINE=InnoDB
DEFAULT CHARACTER SET utf8;

-- ----------------------------------------------------------------------
-- Session tables
-- used for storing sessions data
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS membership_sessions;
CREATE TABLE membership_sessions (
    id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNSIGNED NOT NULL UNIQUE REFERENCES membership_users(id),
    token VARCHAR(64) NOT NULL,
    created_at INT UNSIGNED NOT NULL,
    expires INT UNSIGNED NOT NULL
)
ENGINE=InnoDB
DEFAULT CHARACTER SET utf8;

-- ----------------------------------------------------------------------
-- Password Reset Codes tables
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS membership_pswd_reset_codes;
CREATE TABLE membership_pswd_reset_codes (
    id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    created_at INT UNSIGNED NOT NULL,
    user_id INT UNSIGNED NOT NULL UNIQUE REFERENCES membership_users(id),
    code VARCHAR(64) NOT NULL,
    expires INT UNSIGNED NOT NULL
)
ENGINE=InnoDB
DEFAULT CHARACTER SET utf8;



