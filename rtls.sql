CREATE DATABASE rtls;
USE rtls

CREATE TABLE `ap` (
  mac varchar (12),
  radio_bssid varchar (12),
  mon_bssid varchar (12),
  PRIMARY KEY (`mac`)
) ENGINE=InnoDB;

CREATE TABLE `connection` (
  timestamp int unsigned,
  client_mac varchar (12),
  ap_mac varchar (12),
  age int unsigned,
  associated tinyint,
  channel tinyint unsigned,
  data_rate varchar (12),
  rssi smallint,
  noise_floor smallint,
  PRIMARY KEY (timestamp, client_mac, ap_mac)
) ENGINE=InnoDB;

CREATE USER `rtls`@`localhost` IDENTIFIED BY 'SECRET';
GRANT SELECT, INSERT, UPDATE, DELETE ON rtls.* TO `rtls`@`localhost`;
