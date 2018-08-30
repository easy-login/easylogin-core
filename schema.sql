-- MySQL dump 10.13  Distrib 5.7.23, for Linux (x86_64)
--
-- Host: 192.168.9.89    Database: nhatanhdb
-- ------------------------------------------------------
-- Server version	5.7.22-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `admins`
--

DROP TABLE IF EXISTS `admins`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `admins` (
  `_id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime DEFAULT NULL,
  `modified_at` datetime DEFAULT NULL,
  `username` varchar(20) NOT NULL,
  `email` varchar(32) NOT NULL,
  `password` varchar(64) NOT NULL,
  `salt` varchar(8) NOT NULL,
  `fullname` varchar(64) DEFAULT NULL,
  `address` varchar(128) DEFAULT NULL,
  `phone` varchar(12) DEFAULT NULL,
  `company` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `admins`
--

LOCK TABLES `admins` WRITE;
/*!40000 ALTER TABLE `admins` DISABLE KEYS */;
INSERT INTO `admins` VALUES (1,NULL,NULL,'tjeubaoit','anhtn.bk@gmail.com','1','2',NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `admins` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `apps`
--

DROP TABLE IF EXISTS `apps`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `apps` (
  `_id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime DEFAULT NULL,
  `modified_at` datetime DEFAULT NULL,
  `name` varchar(64) NOT NULL,
  `api_key` varchar(128) NOT NULL,
  `callback_uri` text NOT NULL,
  `allowed_ips` varchar(512) DEFAULT NULL,
  `description` varchar(512) DEFAULT NULL,
  `owner_id` int(11) NOT NULL,
  PRIMARY KEY (`_id`),
  KEY `owner_id` (`owner_id`),
  CONSTRAINT `apps_ibfk_1` FOREIGN KEY (`owner_id`) REFERENCES `admins` (`_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `apps`
--

LOCK TABLES `apps` WRITE;
/*!40000 ALTER TABLE `apps` DISABLE KEYS */;
INSERT INTO `apps` VALUES (3,NULL,NULL,'TestApp','passw0rdTec','http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallback|http%3A%2F%2Flocalhost%3A8080%2Fauth%2Ffailed',NULL,NULL,1);
/*!40000 ALTER TABLE `apps` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_logs`
--

DROP TABLE IF EXISTS `auth_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_logs` (
  `_id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime DEFAULT NULL,
  `modified_at` datetime DEFAULT NULL,
  `provider` varchar(15) NOT NULL,
  `nonce` varchar(32) NOT NULL,
  `callback_uri` varchar(2047) NOT NULL,
  `callback_failed` varchar(2047) DEFAULT NULL,
  `ua` varchar(511) DEFAULT NULL,
  `ip` varchar(15) DEFAULT NULL,
  `status` varchar(15) NOT NULL,
  `once_token` varchar(32) DEFAULT NULL,
  `token_expires` datetime DEFAULT NULL,
  `app_id` int(11) NOT NULL,
  `social_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`_id`),
  KEY `app_id` (`app_id`),
  KEY `social_id` (`social_id`),
  CONSTRAINT `auth_logs_ibfk_1` FOREIGN KEY (`app_id`) REFERENCES `apps` (`_id`),
  CONSTRAINT `auth_logs_ibfk_2` FOREIGN KEY (`social_id`) REFERENCES `social_profiles` (`_id`)
) ENGINE=InnoDB AUTO_INCREMENT=46 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_logs`
--

LOCK TABLES `auth_logs` WRITE;
/*!40000 ALTER TABLE `auth_logs` DISABLE KEYS */;
INSERT INTO `auth_logs` VALUES (1,'2018-08-23 10:29:50','2018-08-23 10:29:53','line','y4dMgIq9iQH2jWoG','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','6KoVkAueGiW1ROTeWllffcCFgRxaNAgB','2018-08-23 10:39:12',3,1),(2,'2018-08-23 10:29:59','2018-08-23 10:30:02','line','zhlTtk1LDf83zl3d','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','81fXxC6p6lQw68Kar9rIdys9a6peZE2Y','2018-08-23 10:39:21',3,1),(3,'2018-08-23 10:30:08','2018-08-23 10:30:21','amazon','HXVBf4UnVPrRUclJ','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','bIM00txiz4Hsfcbv7M1oiN1sXhwJfiLm','2018-08-23 10:39:41',3,2),(4,'2018-08-23 10:30:27','2018-08-23 10:30:44','yahoojp','6dco60butE9qP9jL','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','0WdmtcqlzR8Sy7UiZr6T4v4q4SEMbRWq','2018-08-23 10:40:03',3,3),(5,'2018-08-23 11:13:18','2018-08-23 11:13:22','line','UI5aQMY4B7xFIIBa','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','dxC2nTOvVyHuPdnaq9hYEXNr96966V7Q','2018-08-23 11:22:41',3,1),(6,'2018-08-23 11:38:50','2018-08-23 11:38:53','line','6AgdNWqsHCSkGxuH','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','2U7TnoEd9JN87bx4gJpwywJeblboMxIp','2018-08-23 11:48:12',3,1),(7,'2018-08-23 11:42:20','2018-08-23 11:42:29','line','t3sjKBGB3qdxeJuM','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','DkmMh3WF8lhsBoe7JsfyNLzOThweZg6t','2018-08-23 11:51:48',3,1),(8,'2018-08-23 11:43:10','2018-08-23 11:43:13','line','V195hbK8KuBH0RaZ','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','smddS0FIsxVeN7roNk861dSfvsvYDJsS','2018-08-23 11:52:32',3,1),(9,'2018-08-23 11:47:18','2018-08-23 11:47:21','line','6LmnARUUuIuMMFCk','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','DaZ6a9ZFLRqw0UtzZufuy4NAKG14xxvx','2018-08-23 11:56:40',3,1),(10,'2018-08-23 11:49:42','2018-08-23 11:50:34','amazon','OXEVKyXw6fflx11I','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','9n4q2rveQliZtfnPiQIbZMhZaPV5NGTc','2018-08-23 11:59:54',3,2),(11,'2018-08-23 11:55:39','2018-08-23 11:55:42','line','1W6yxIAmIo6QvS38','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','bnsZeMwrUtJXR590MbjmIuK17pqq4WkW','2018-08-23 12:05:01',3,1),(12,'2018-08-23 11:56:25','2018-08-23 11:56:27','line','CMvuAeLzWBzDtsPx','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','cHJbJawxCmkh1dG7rWXtYRrNdjCLDmcO','2018-08-23 12:05:47',3,1),(13,'2018-08-23 11:59:18','2018-08-23 11:59:20','line','jN9X5RDc6swg1mwk','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','Y01dEtppA5ukDSXYxR1BPOEmJYi5zStR','2018-08-23 12:08:40',3,1),(14,'2018-08-23 12:00:21','2018-08-23 12:00:23','line','tzeS9lQTgsBM2Usx','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','KdOhc0wN8HUIynNb7ardOosbV6FkIeSd','2018-08-23 12:09:43',3,1),(15,'2018-08-23 12:01:09','2018-08-23 12:02:07','line','BJ9aLSk7DflylfHT','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','pT9nC4EyE6nsVG8SrmJjGlr4L1luH9do','2018-08-23 12:11:27',3,1),(16,'2018-08-23 12:03:02','2018-08-23 12:03:05','line','o603mMXGnZhCCfe1','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','1GI2fkpxeZmpGjWwzBl7I5HsyfiYDVop','2018-08-23 12:12:24',3,1),(17,'2018-08-23 12:57:28','2018-08-23 12:57:30','line','bqjLwlPZ9rvB0IQH','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','vxjgalNZ2oWPyXMJ8TDCrBz1ytld6zw5','2018-08-23 13:06:50',3,1),(18,'2018-08-23 12:59:35','2018-08-23 12:59:38','line','jsuoE1XQKU6Hd6sK','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','MO6RnKl2lj8DcCiQsOFLtqzK0YFWnWvN','2018-08-23 13:08:58',3,1),(19,'2018-08-23 13:00:09','2018-08-23 13:00:11','line','wlH9Zy8XIljdOjtp','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','hUIYXqZ4TS2PEvXA6QFpRpj9HlK5hcMI','2018-08-23 13:09:30',3,1),(20,'2018-08-23 13:01:00','2018-08-23 13:01:02','line','UOzvm6vNYHeYEiws','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','70T93pQBcWUSkoOZp3eX2IMLm8tXPexl','2018-08-23 13:10:22',3,1),(21,'2018-08-23 13:01:40','2018-08-23 13:01:43','line','krZYID6d4z2WWhJ5','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','SIlHAvGLpCte6UjOx86KAAiVgKFGf3yN','2018-08-23 13:11:02',3,1),(22,'2018-08-23 13:02:09','2018-08-23 13:02:12','line','m0Z3ZdvUl1x6BiEC','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','rOarwYPOsWwI28R8QFip5XHxeo0grflZ','2018-08-23 13:11:31',3,1),(23,'2018-08-23 13:03:16','2018-08-23 13:03:18','line','uwMpozrK0dcahZoD','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','e1jeUzP1V5gx3nsRIWbL6JaGU7E26Cxb','2018-08-23 13:12:38',3,1),(24,'2018-08-23 13:05:36','2018-08-23 13:05:39','line','R7GtR03Drk22E37o','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','0EA87bgMyuiq8fnj9LDznqpLgpo7M2xW','2018-08-23 13:14:59',3,1),(25,'2018-08-23 13:06:09','2018-08-23 13:06:17','amazon','d76lWHiVaFdwUNtH','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','W1myIEeyfcBxH5wkE3wkMhB1vcPw6MMO','2018-08-23 13:15:37',3,2),(26,'2018-08-23 13:06:30','2018-08-23 13:06:38','yahoojp','QcO82iiMvTkWnoC6','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','R8gJKA65y9AaRUnjLxvEY0LOAXAJYRy5','2018-08-23 13:15:58',3,3),(27,'2018-08-23 13:34:22','2018-08-23 13:34:25','line','OTRFIaESCNC5uqSW','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','gnuRbKP0DayAlr5gEHV4Wt3lEVcH85dA','2018-08-23 13:43:45',3,1),(28,'2018-08-23 13:34:30','2018-08-23 13:34:32','line','8czpykmWopqye3C3','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','rItOxFIQhmGe1nn52GdPMTx5Sz0OCuxh','2018-08-23 13:43:52',3,1),(29,'2018-08-23 13:58:02','2018-08-23 13:58:10','yahoojp','9DLC7vrZHwR8iHN1','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','gewdl0EmakdVDu9O7Pv2FUE6T9PEOhJa','2018-08-23 14:07:30',3,3),(30,'2018-08-23 14:00:38','2018-08-23 14:00:41','line','naBZ4ZOoC4T5v08q','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','mF8KCUUVggUFdS9IWDalUtI27fpfAq0N','2018-08-23 14:10:00',3,1),(31,'2018-08-23 14:56:49','2018-08-23 14:56:57','amazon','XaRHhLugnfkBfPI2','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','p3uHDstdoBhNFjmE1Qgvak9XNGxAxRv1','2018-08-23 15:06:17',3,2),(32,'2018-08-23 15:22:48','2018-08-23 15:23:03','yahoojp','lwoK6ZkfYM87Xtkl','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','7viDSAiQ4yiO2CUuwUe2vS7bGQwMCY2g','2018-08-23 15:32:22',3,3),(33,'2018-08-23 15:23:05','2018-08-23 15:23:09','line','shv42Ez1SsrAkzGp','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','mcZtuYIiS7K4KSsERJ3zR23MPL5EmJ1a','2018-08-23 15:32:29',3,1),(34,'2018-08-23 15:23:55','2018-08-23 15:23:59','line','wtyYNABkkgsF8cp7','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','HaDssR5d8KLv3dbMIUubsSzb4tgACglJ','2018-08-23 15:33:19',3,1),(35,'2018-08-23 16:20:37','2018-08-23 16:20:37','line','CJPUkaOXAW9lAWyF','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL),(36,'2018-08-23 16:22:36','2018-08-23 16:22:36','line','ryRoLHdo5tSz768R','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL),(37,'2018-08-23 16:28:55','2018-08-23 16:28:55','amazon','7L9Sx1LnudKtUdnP','http://localhost:8080/auth/callback','http://localhost:8080/auth/failed','Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL),(38,'2018-08-23 16:34:04','2018-08-23 16:34:13','yahoojp','CLdXJeLq8abnESoo','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','0MdJWnZjN1xEe38AEmGakBXVtVWPMUG7','2018-08-23 16:43:33',3,3),(39,'2018-08-23 16:37:34','2018-08-23 16:40:39','amazon','GZN2vNYna8j56PvF','http://localhost:8080/auth/callback','http://localhost:8080/auth/failed','Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','succeeded','gP6SJ9WTqEXapOCTfYrjW8WJkDbydF28','2018-08-23 16:49:59',3,2),(40,'2018-08-23 17:23:44','2018-08-23 17:23:44','line','7yphwsCMaxcDUYB9','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL),(41,'2018-08-23 17:24:58','2018-08-23 17:24:58','yahoojp','Is1TmGSbfws0QmRz','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL),(42,'2018-08-23 17:25:53','2018-08-23 17:25:53','amazon','tAKVFbCSDaIifnrs','http://localhost:8080/auth/callback','http://localhost:8080/auth/failed','Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL),(43,'2018-08-23 17:28:22','2018-08-23 17:28:22','yahoojp','38w2ppzcYoPzkT1I','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL),(44,'2018-08-23 17:30:32','2018-08-23 17:30:32','line','SX22RHUSKQhTFDsB','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL),(45,'2018-08-23 17:33:35','2018-08-23 17:33:35','line','UT5yuyLwUGdn54R4','http://localhost:8080/auth/callback',NULL,'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0','127.0.0.1','unknown',NULL,NULL,3,NULL);
/*!40000 ALTER TABLE `auth_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `channels`
--

DROP TABLE IF EXISTS `channels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `channels` (
  `_id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime DEFAULT NULL,
  `modified_at` datetime DEFAULT NULL,
  `provider` varchar(8) NOT NULL,
  `client_id` varchar(128) NOT NULL,
  `client_secret` varchar(256) NOT NULL,
  `permissions` varchar(1024) NOT NULL,
  `app_id` int(11) NOT NULL,
  PRIMARY KEY (`_id`),
  KEY `site_id` (`app_id`),
  CONSTRAINT `channels_ibfk_1` FOREIGN KEY (`app_id`) REFERENCES `apps` (`_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `channels`
--

LOCK TABLES `channels` WRITE;
/*!40000 ALTER TABLE `channels` DISABLE KEYS */;
INSERT INTO `channels` VALUES (1,NULL,NULL,'line','1600288055','9dbe2e69e669ec9f750a9a9b034ce481','profile|openid|email',3),(2,NULL,NULL,'amazon','amzn1.application-oa2-client.e4f978fd4ef347ddbf8206d16f0df5eb','ad90102af6bb3de8bd0338bba92000ff427f7a47467460b49aa0a0c0ef2a8592','profile|postal_code',3),(3,NULL,NULL,'yahoojp','dj00aiZpPXdLd3FmMEVmN01VbyZzPWNvbnN1bWVyc2VjcmV0Jng9N2U-','0KaCAWAgFA9vT4DqMRwiV6y4F0sHPxbZijRElxNw','profile|openid|email|address',3);
/*!40000 ALTER TABLE `channels` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `kafka_offsets`
--

DROP TABLE IF EXISTS `kafka_offsets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `kafka_offsets` (
  `group_id` varchar(64) NOT NULL,
  `topic` varchar(64) NOT NULL,
  `part` int(11) NOT NULL,
  `from_offset` bigint(20) NOT NULL,
  `to_offset` bigint(20) NOT NULL,
  `dt` datetime DEFAULT NULL,
  PRIMARY KEY (`group_id`,`topic`,`part`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `kafka_offsets`
--

LOCK TABLES `kafka_offsets` WRITE;
/*!40000 ALTER TABLE `kafka_offsets` DISABLE KEYS */;
INSERT INTO `kafka_offsets` VALUES ('test4','oplog-test',0,82576,82576,'2018-07-12 16:09:30'),('test4','oplog-test',1,82558,82558,'2018-07-12 16:09:30'),('test4','test',0,428670,428670,'2018-07-18 17:16:30');
/*!40000 ALTER TABLE `kafka_offsets` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `providers`
--

DROP TABLE IF EXISTS `providers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `providers` (
  `_id` varchar(8) NOT NULL,
  `version` varchar(8) DEFAULT NULL,
  `permissions` varchar(2048) NOT NULL,
  PRIMARY KEY (`_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `providers`
--

LOCK TABLES `providers` WRITE;
/*!40000 ALTER TABLE `providers` DISABLE KEYS */;
/*!40000 ALTER TABLE `providers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `social_profiles`
--

DROP TABLE IF EXISTS `social_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `social_profiles` (
  `_id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime DEFAULT NULL,
  `modified_at` datetime DEFAULT NULL,
  `provider` varchar(15) NOT NULL,
  `pk` varchar(40) NOT NULL,
  `attrs` varchar(4095) NOT NULL,
  `authorized_at` datetime DEFAULT NULL,
  `linked_at` datetime DEFAULT NULL,
  `deleted` smallint(6) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `user_pk` varchar(255) DEFAULT NULL,
  `app_id` int(11) NOT NULL,
  `login_count` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`_id`),
  UNIQUE KEY `pk` (`pk`),
  KEY `user_id` (`user_id`),
  KEY `app_id` (`app_id`),
  CONSTRAINT `social_profiles_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`_id`),
  CONSTRAINT `social_profiles_ibfk_2` FOREIGN KEY (`app_id`) REFERENCES `apps` (`_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `social_profiles`
--

LOCK TABLES `social_profiles` WRITE;
/*!40000 ALTER TABLE `social_profiles` DISABLE KEYS */;
INSERT INTO `social_profiles` VALUES (1,'2018-08-23 10:29:53','2018-08-23 15:49:27','line','5821e4a8ab9eda54e008aa59f57b56c8a0c5e2da','{\"userId\": \"U0583367f757d14337a5c184c24f0f5f1\", \"displayName\": \"bangbang\", \"pictureUrl\": \"https://profile.line-scdn.net/0hG4ukIoXZGBtIEjUgCvdnTHRXFnY_PB5TMH1Rez0UTi4ycAoacyYCejgXFXwxK1ZOIHECe2URFH8x\"}','2018-08-23 15:23:19','2018-08-23 15:48:47',0,2,'tjeubaoit',3,5),(2,'2018-08-23 10:30:21','2018-08-23 16:40:39','amazon','feb99e2123614d4941139fd61399313ab0cce63a','{\"user_id\": \"amzn1.account.AG4C53II4EPJZOQNYV7HVSJLRFGA\", \"name\": \"tjeubaoit\", \"email\": \"anhtn.bk@gmail.com\"}','2018-08-23 16:39:59','2018-08-23 13:54:46',0,2,'tjeubaoit',3,3),(3,'2018-08-23 10:30:44','2018-08-23 16:34:13','yahoojp','aa24cf1de98b07d08d1be59b8cb44def54f580c3','{\"sub\": \"EOGKIUGOF5TZZTFKZ5FI7PK23A\", \"gender\": \"male\", \"locale\": \"ja-JP\", \"email\": \"anhtnbk2810@yahoo.co.jp\", \"email_verified\": true, \"address\": {\"country\": \"jp\", \"postal_code\": \"2720137\", \"region\": \"\\u5343\\u8449\\u770c\", \"locality\": \"\\u5e02\\u5ddd\\u5e02\", \"formatted\": \"\\u5343\\u8449\\u770c\\u5e02\\u5ddd\\u5e02\"}, \"birthdate\": \"1990\", \"zoneinfo\": \"Asia/Tokyo\", \"nickname\": \"Son Nguyen\", \"picture\": \"https://s.yimg.jp/images/account/sp/img/display_name/user/512/06.png\"}','2018-08-23 16:33:33','2018-08-23 13:57:52',0,2,'tjeubaoit',3,3);
/*!40000 ALTER TABLE `social_profiles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tokens`
--

DROP TABLE IF EXISTS `tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tokens` (
  `_id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime DEFAULT NULL,
  `modified_at` datetime DEFAULT NULL,
  `provider` varchar(15) NOT NULL,
  `access_token` varchar(2047) NOT NULL,
  `refresh_token` varchar(2047) DEFAULT NULL,
  `jwt_token` varchar(2047) DEFAULT NULL,
  `expires_at` datetime NOT NULL,
  `token_type` varchar(15) DEFAULT NULL,
  `social_id` int(11) NOT NULL,
  PRIMARY KEY (`_id`),
  KEY `social_id` (`social_id`),
  CONSTRAINT `tokens_ibfk_1` FOREIGN KEY (`social_id`) REFERENCES `social_profiles` (`_id`)
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tokens`
--

LOCK TABLES `tokens` WRITE;
/*!40000 ALTER TABLE `tokens` DISABLE KEYS */;
INSERT INTO `tokens` VALUES (1,'2018-08-23 10:29:53','2018-08-23 10:29:53','line','eyJhbGciOiJIUzI1NiJ9.T5ztHUUPX760lp_cNcjzsSvsXVNCSp3GQuDnKc7lpUKtH4dDZD9L8TxlnKi91Y17n9gSdrhfmRbCytH85ZObdGLtY_iNCUr5h9O0yVYgmzX4-D2URiChqCKuWoSJZwaiS5AZtEjmVpSuTKEwFC5TqVlrGPUN_jHgg3JjSP5BtbE.ULhKtaSzbwoDrgrgjKrTTLHm6ladAGZvetSdOrqQuks','NOoeq9JMzUvIgr4XCCF2','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNDk5ODU1MSwiaWF0IjoxNTM0OTk0OTUxLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.LFzP_Txmy96YROjIeDg3IxPxdmhbbn12iboLti1VARo','2018-09-22 10:29:12','Bearer',1),(2,'2018-08-23 10:30:01','2018-08-23 10:30:01','line','eyJhbGciOiJIUzI1NiJ9.8obcYVi44Q6VmlQHsrkUjBJC_T1X92aRFajkOhg9dmmskuZ2LLzdl5slWHUKx_ORbkhkqOkw1dRVP4ERWYvgrLsTyjs6f6D3lO9MHmHCuob2G5oUU3V9leh7sfHyESNMXllJfY2vst0nNo0v5G24uWyoWRG_EKgsDbTLt2haeCc.wWUSAQB1Td43EYDKEpItSB-_as_DrvXGPEdpMQNylMk','P9XCqkzEmIxUEGv2Rkzb','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNDk5ODU2MCwiaWF0IjoxNTM0OTk0OTYwLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.CjESnsNbnrxOicbixhSUPojcvcePf9CxQvxXlCzp86c','2018-09-22 10:29:21','Bearer',1),(3,'2018-08-23 10:30:21','2018-08-23 10:30:21','amazon','Atza|IwEBIKjjxkTYGFQcmVIpuOJ89xb2u3YuIhzNvfzXUIA0r6pNhmgrriH8ftod2FWgxXR100cKw_w8gVz0eNX2l_smgHkkqHaGAhZ-aSVnWvjiA6r-p6KqBQtrQixdxQp_tJoEBzk5m7IrvYfWzvCIc-XtllXNGO0xxDFPTcx5GkxYv3w0DNOMVSpms2b1J81p6iFAIAeNND6QQiE5T-Tn87MJrmKeOSfX04RfAkgMTrMnLArLmHJ0ml7ZAPjsmP2Fzpid_kqKCISEHwLy5EZwFMpGjMHJyt5-bqd6JNcgWfxVOD4ucpgF3nQPQwqVVQ_m6eB_3jWEJcRMNW-dvb6tYHdDOzVfrxfEHB81UYPxLC2XH_jdEn1TcE0w3o4bqSj8RmpMzmFNEjMes1_nvyZuIf0arXf4q33ApO7DfZfBtkFw28posq7wv4_kaVJvtOub2d4uje8JNHp3s8RF4KEFcOZVzPhimtdW2La-JmKiNGfDowIhHpB7vhcIna2fNJs_rnwjvlrstBI7da006nezGS_1p19C_zY9FlkyAiYPPL6FU9KVE6jKdGTOoDdjSSeZnmqIoDg','Atzr|IwEBINvWR3h6XEuxNjx_443aKZ27gAVM7v2BVcgaf3XjaElQ--LHowYBY0h5cv-Pb7TM-MQCu15PefB9WA7NQatpQNSZaOSp02jtO3Np67KPdsi9ttLrbG4EsrUGk9gqmTb42H9iUHKMwIbRRwsMq71FCwg_pKemxhpozvu7lkJ0npYsjaT90jRiKLyXHxHD5C4DmA7kbDqO87pign9UguxDhIgNU_UPGem9LFXN_ZbpNfL-UFkQ2p843_6bJ82YNN8MqmteMcZH6usi45CKAImw8sjJp2y8VP6dmNQa6PuEXMPAtk-r-qx1oaJqEzoHvVRJOTyj4eNR7T2oILWurtOpxWf6CY9GVF6fHZMghL7RU0QeczPKwIvPwrKaqNHhv7vpnzZK02mLIYcDTjwx0kO1ZcDE9u00mlduv3yNW-eyvGcONncgtzBGNpLz39uDB4OA0e8pnG2bdwVdTi2uUtXRB90aoEuWuDtB5O_a6uBuHBkRVGavH6wdTvLVhwHh7TjYJkHgBN5I254rIKNsP6ZY_KjG',NULL,'2018-08-23 11:29:41','bearer',2),(4,'2018-08-23 10:30:44','2018-08-23 10:30:44','yahoojp','fb7r3ngA4awLKdjMzHKuzCap7pf_ANPxVH.e733XvoZUT3GUVlZysBKRFVhg_LDjtaB7Jju.PpLdz1bK2ZLXXGs2uiqP.sOhkPQCLHEGR16cnojMhljZ5ayzs.K2tbOQdkjyJJui1lRxxB_v2RXQEXE12rQ7uiNzQp2oVh2PyRymswImJucBwx1BNMG569bpjKaAuX4faLiz.MTZm0JSaGPuYMbB4.uU5K.rpn1cPrcvG9rXNWMKQTk1jb2AS7VYdimbJtP0nEDWYGgCAOucOvMv2eO_aGTIZ8Vm5yJ.BSm.dOQTB6eGZ00qNmu0ATFJzM0aI9A1wp8gIeslxp2OUAC.dP33uS7Nx0YmeiLPHZE0rDUMWXuJoDZJe4ZnlbR.J8iC9qBe3N2iE4CWKIJbhN.ZIpWQ.uonCC3xqugGsXdxstoyn_w3NlXJQKj2fBGdfd3GO6SFTtCbXAnYd6eCskEwm8AbSS73TEVW3ogI.u4tIERc581v9.d4R325dScH8.afGgy1gTKWk6p5caaIi6uBEShyhgazfO0oB_ljE29oaMrxiERIXPJ16zWVuSVVfzYdEJJmrpsMAioBoU10whIlalfEMhD9lFaMDJir0o8KXO3m1H97IosVje2WZPlYXrR_8JurbBboYAwGM7o63wiRHq4Zi8lJ_3HHmZ1r9uxD24x6987ESQNwjTbkyLDhs4I_BMjVi_XS3EavuL8LzbdF0uJFakznu44S74OPdPzU1rGsIpAQgYdzA5jANlFnL_8XM2auWYKuZI1C21BUG219ElF88hIguivwPKYsDnPqJoawVVH9hW9nntPVBpNgU5h0','n6x.TRNnPp4yr65dyKfdDtiBvkTwbntwx_B22XIqxGujUAq5IwlAx2..JPT.eFqs5i_HNnca','eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjBjYzE3NWI5YzBmMWI2YTgzMWMzOTllMjY5NzcyNjYxIn0.eyJpc3MiOiJodHRwczpcL1wvYXV0aC5sb2dpbi55YWhvby5jby5qcFwveWNvbm5lY3RcL3YyIiwic3ViIjoiRU9HS0lVR09GNVRaWlRGS1o1Rkk3UEsyM0EiLCJhdWQiOlsiZGowMGFpWnBQWGRMZDNGbU1FVm1OMDFWYnlaelBXTnZibk4xYldWeWMyVmpjbVYwSm5nOU4yVS0iXSwiZXhwIjoxNTM3NDE0MjAyLCJpYXQiOjE1MzQ5OTUwMDIsImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNTM0OTk0OTk5LCJhdF9oYXNoIjoiQUFQRmh1MUw2MkhuUFJBNk0tMDMyQSJ9.kYoyg1l8Mvq0oV_TUvewZSfhooRhDK0ma-O2IncBSZkjoi1btgSYqWQnrTkPc2qfm2k_t2kFC3lCNOh0Sd6XCJV1na5lQZ6eCJu8g_shFjYc9ckDBYMPlAAQ1-BWuQ3debkgpdDuJnzmQdvmcqd9g1MuBod891jfEC79Z3LkFK6UAp8-XYO80uOZjjdBqjVtxB2OuSAXj5O2x7cbTW1TqA0CnHTK1zydtKFMJIy3LZiL9flZURqkm-FBfIJouYiOaMxG53HMeecA07NecNyN9oURV_sBmUC_4XuUtON3_vaMUGTAs9UKTcjfJGb6zSv4iJbaOHZSX1H2gX-MdLnEig','2018-08-23 11:30:03','Bearer',3),(5,'2018-08-23 11:13:22','2018-08-23 11:13:22','line','eyJhbGciOiJIUzI1NiJ9.Z-K2R3d7Lql1n2_lMkt8KcgbcEmCWSlGcsQ-TITqA3NPRbF1lwIT2k53nD9gCzbQyB8Jz7zSEEU5gUUec8dHcepVg6iR03yyq_C0TsR79f0IJuWxbDCD2pLH1d4lM7OkDqDF9QxCoj3I6i5ZHpjqdiRXz0Tj65IbUUop0pNch3E.KTDUNDgpUkuZnQSYA3Up1RZ86vHGuj3rJc12OgHBAB4','DWXGzhui89gCnQPfTfll','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMTE2MCwiaWF0IjoxNTM0OTk3NTYwLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.s7qhgwweXjvkGdsUI33zmObsY0eaCTMbFxE7EaGDrN8','2018-09-22 11:12:41','Bearer',1),(6,'2018-08-23 11:38:53','2018-08-23 11:38:53','line','eyJhbGciOiJIUzI1NiJ9.0YnxkxUIAe_OiM7g3Unokk4V6ugig7I3wrRcbXLPR3z1LhUDB-1mosk3Jo6eEzg-GKZf7DUxmoRQyNGzbVuCYyQY9Zng2mEyNMretj832Ovz0QeF1sN-FYJa7t2gUtJ6GcqHHISW_Oxg9FrQIrKgl6tHIzBANz7x5y2H-EOazAA.jg27TNP2AprCX3R8PltVcL8V8GToE_bxEKleqkY17h8','fLHvi8Miv53r74mLEfzm','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMjY5MSwiaWF0IjoxNTM0OTk5MDkxLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.AM_juKaYfXaNqLAGqwTFbezIMzp4g-eoHnEeM5ziJqc','2018-09-22 11:38:12','Bearer',1),(7,'2018-08-23 11:42:29','2018-08-23 11:42:29','line','eyJhbGciOiJIUzI1NiJ9.7eF7x_aPekYLnrWFtXwEQmEs79NUt107RPI-jueqiVz_vz9f9Eu7lxv4MLjRxr_PscRfSIk3OZyjEjsJIr2VLTRphm1v6ZUzSrZOOmug3OG0d-rvCvBCOMLe4JqErRtPj88hsqWJy2BQP9kOO_j6sthS4Q_xwjuLtLnuXaumAts.-iRuXd90RyMIhACjWUquQdWfhLEfKB35V8LaNDvFYAM','LgMGivNcTMfyXFGS2fpA','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMjkwNywiaWF0IjoxNTM0OTk5MzA3LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.eCQoPLu1BsfgHF2sESHEVSEE7fR8OgVyfOaeTrMSXuk','2018-09-22 11:41:48','Bearer',1),(8,'2018-08-23 11:43:13','2018-08-23 11:43:13','line','eyJhbGciOiJIUzI1NiJ9.WU_2CwyNLc6qQmVgYaRekWFehO1CO_RBE8aCs3Eb50ipY3cCHczMtAyiQrRPj36w0ke9e1TP9z5NmSdAoht40FmuQVk2DAaeb7Dgjtd87L8O09DZIdXNSbs8Ix8Ews09muKmXsDyDG8tCr5-Rynk-HCTQh4xH_NqWA8jzA3BzgQ.aW36L9dClMDAKmFDmgXw_FTVQbEV__QYv6GA-IUZ1AI','Qv5gCvycMGQqRvMyLjQN','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMjk1MiwiaWF0IjoxNTM0OTk5MzUyLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.ON9ruFruaNr_CJdqcBBRbGmrUBZxgsF1zSdsQl58jHA','2018-09-22 11:42:32','Bearer',1),(9,'2018-08-23 11:47:21','2018-08-23 11:47:21','line','eyJhbGciOiJIUzI1NiJ9.169Mw4jhANmtoHQpaHjXxdmuyh3UETb4uGnMcofiqhJCjX48k3aKCX_582qs9ado2QeFw8EBRLQpWhA83xfWtRADT1ql54OaEJqj-VBdIGua82dUiiSLjLsK_6jtRvnEoOPv07HEi7jvS5oAr02eeiBVdtiNKu00auVUnmqPg1A.RZpTi3WJtnxg3b1pHGcqR5ZWhUpOU5HIez0pf9MtkHQ','Vm20Wh88GzbN98zmHtjd','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMzE5OSwiaWF0IjoxNTM0OTk5NTk5LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.yj5IO-wX4DOhR1p4A3U1-q-KhzmIJYWWFz-rmhk2gV0','2018-09-22 11:46:40','Bearer',1),(10,'2018-08-23 11:50:34','2018-08-23 11:50:34','amazon','Atza|IwEBIFBQH_m8PJfqhqnAEtTdunJ38vuUid3QgINez2iNnv_LlFEW63K5DVZPOE8-nJZbsVFPXRRcuuBiPtQTBauTIYlS7DpFmEPPjwFHZQnUG5fBSvGt3kc4E4pAHJsYaXwi5v7T5WGcrEQwd6GuZHMsa__cJTfmtnscs9DDP4S-Mviv_3amsHfz_WeliVIrhu9vW0ZyxYi2MsRp_TYvrZlBKx6w4JOLHJbyTh1tlPxh82Bxu6XoiLoYKbT0BjMngEd5A5Lng2tOA_fwRhHJS2pZsWzpip8XeZpabYvKJs8jPGJmHgABNH1gy2bZOuGASMunEVAWOLu3Gc9TgzwRvfPCHATLAGk8LyMs-utfuliEDZLEY8b2OgdZv4ZF4OY8MSk3uA6HqShwV0dJND_PWxsv60hInY0bG_oeY3IIDmeF2fy3zcMmDArSp-PsIzw95U-A_yb6K2c7mjDlzjRMC_zEg1wyUrVpBXXWE729uw9NkwYlfhLjZr6EsD-ikVsCKk0R9gprYN7aDwaa27xDRYPkSd1IuCNK6bwoqIC4uSrmHpe4Wd_RrUWP4nseqjhMkAwFKmJd6B_gQqKBFb9ADXdTc2B9chNWGjviJ_O_amLXUjF6Og','Atzr|IwEBII0etHciGw_zYabLxgiW3WXEQr6ln-yQyULSIcvqCzOwy6BVNk3hBufWmfKxNjUSuutltUBxJGlAQUTM-A8BVLUNTLVP17x5CuHigifGUVMrYWB-Qwk8iz249ERUv4WSgNVyo7Ofg-kicqJCXdgKdPm73llC2i-pzYnRFEoahF_aPlB_V94mAEyVVIUufe4DOfgjFTSVRVZksn1F6sis-nTrwXOWeRrGaUJYI4wlZ9IGClo0-6yu1WkV6meB_SHRXWiMJ27MZkXqOp81YdYYuvOiFbr0332Qgth1SLLL_gOdiAR-Fv1NtFJjNbnNeIDwbr9V7cCZNN6HcD5t30Cib5KRQLHIuYg6bYQYnnCd28FuA-TCFde6DikyqBqndBOMB4hag2mHofYf_vohDNhD3qnZLiXo5YT9odi75YyTX_e02vMcxHx3n4MMcBuzUwEUAN1ZHjDxrM7td24089atmGQwoJX4foeBIAT9Qol5omrjsdZVtFLVZrLtQ0coWnLSDjEkFWIpSZxH8Kxb086dPL3Qz0QtKpFNKyUj2uE62UyFlA',NULL,'2018-08-23 12:49:54','bearer',2),(11,'2018-08-23 11:55:42','2018-08-23 11:55:42','line','eyJhbGciOiJIUzI1NiJ9.5Pj3Du1N7jHV_o3KWHxnFgvSXwYv6qtImEL20E0xvO68RGfCKW5jXGUkIl5v3N23HC7jga1ZWhIH_SygVK7vEFFyjvD4fYbn8-AgsnuI1utTvCvuEQP1WLsO_TahRHnB5uBGsLeFYuSZRjbQhI3ohMLOWMUEeQ_Tj-qD1bIvsao.HEKlECazs__Al9RYZqCWJB9NE7VhaNQvOsp6zagMSaE','3c720OaH9Qv5K5Ai8Ds7','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMzcwMCwiaWF0IjoxNTM1MDAwMTAwLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.pY_4U-EAaCdEn3-KqDXNNrezgWPD69mnp6ALz2g9ECA','2018-09-22 11:55:01','Bearer',1),(12,'2018-08-23 11:56:27','2018-08-23 11:56:27','line','eyJhbGciOiJIUzI1NiJ9.IdfFu1vVYEcxkmCfKCcwDIixWdgzqfD94DgppOvuN1zWJpoQyaAVBRXSnS7Z35ktsudfj2taWIRX0lKYyk1ofWtK3Dye_3ULbWHoGQAfz89bA2kiXZLLOvEzqvVTDzcyEFka0hwlo7j5vKrPvDYbyrVjSQL7SKiwNYIbQauDRN8.ZlOXh_-OzWEOYUSXFtiR5SyhqDiip9ZmoUSnNpKV4I8','DpFs2XXGJrEul9zTISNg','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMzc0NiwiaWF0IjoxNTM1MDAwMTQ2LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.N-tYAgsqU6lxLYlQACjMM4MH91eFmlDS3E3-3BZrHCY','2018-09-22 11:55:47','Bearer',1),(13,'2018-08-23 11:59:20','2018-08-23 11:59:20','line','eyJhbGciOiJIUzI1NiJ9.oPjwrx2WosrXFGMVN1APm9To6SwFf45OuM6ITF5fbGWRDx5zpcprV1pSXL-1W9HdpN0TUgV9ZAt0OLaQ6-MsP5Pz1pwoEfPtBqWsXZPkzoAxa416mekQzxVftYP9BmblldV32fEwdvQ9J06D5m-vMOOwuBxg5yek1t8LgLMe360.AkU6ioAyLTVjlFoLlXTbwD44tA0gZTakwRsAddHXssA','JvDBe9f5QDGoGIzHMO9e','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMzkxOSwiaWF0IjoxNTM1MDAwMzE5LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.wRm7ft3q-Y6zeSQ3UyIKj6yxDfJVJAjupNAg72jQ0UU','2018-09-22 11:58:40','Bearer',1),(14,'2018-08-23 12:00:23','2018-08-23 12:00:23','line','eyJhbGciOiJIUzI1NiJ9.0vR4gHr7Q53zeWz4f6a_tw35anAAAnGZ69hEN5NfTz93HQK_lrg8saSTgYn9Esl8qhu9oXvf2FLMyxJFbf58ikovZCFj8L8n9h_cbJrFlyGH0ubmF_a-yOU9V_FIoRoiH4Hk1eLmxWifvtHxMnWk00QTeI7Xr_yoplNLJzUB0gQ.2vU3tV0fvss5Mxa4pBOvIf01FFgGLb9eENr0E7WipdY','kZhs3u2oLacaruJGwuvv','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwMzk4MiwiaWF0IjoxNTM1MDAwMzgyLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.pWv6nHuYJ_3eI1aeWMBkNVTzO52bnXHk0K59wpNHt1M','2018-09-22 11:59:43','Bearer',1),(15,'2018-08-23 12:02:07','2018-08-23 12:02:07','line','eyJhbGciOiJIUzI1NiJ9.hgmDx7JTVGEZNaxH1cvUBJq-kaZneefzf3EZME4arY6ADyjOjy_Op8Dg3NE_4F4KnMU4EGEJ0bEcsQsW0gKcqLkS28UDHXdL-03Lsd4GU3Dp80yNquaSkoSS9YpSpLDEXcxPTlS6ia6FRE2ZtwpHO8RLB7Pv3T8lGPV9vCV7lS0.q_9yY7TomCORArf8zjaWGZqMEzVJCHmYsm_sg9luZE4','seAJJOnZRxaUTquwiDVQ','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNDA4NiwiaWF0IjoxNTM1MDAwNDg2LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.cWFh96nObx3wIk2DuBUOjlLFwecbsmFo2M20GXohZMs','2018-09-22 12:01:27','Bearer',1),(16,'2018-08-23 12:03:05','2018-08-23 12:03:05','line','eyJhbGciOiJIUzI1NiJ9.5KP4aJF8z0Pgr-NwmZQB9TbHDVVAOJdDLYNqxCrGqAWA6d7vJzAuVn3TNze7TxfxRjR_pQZ1vRWlZJb7WwuH5KDKwtMhppCcOP5dQb8Ro8x5a6Q4wJeonkT2NuuWCK1eAdjMmnZ2pFeTc5em2GWY1etbi3wIliO_f1t_EIGastc.6zlcseojUvvnSR6xQIcpyNWiq_ekwdtHfonMWCVAK24','CSv6ggPppNo5N0W23wty','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNDE0MywiaWF0IjoxNTM1MDAwNTQzLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.ObO1vwJ6bzKuAlvGkxZSTzYWysVfyLpc3oHqAY2pwlg','2018-09-22 12:02:24','Bearer',1),(17,'2018-08-23 12:57:30','2018-08-23 12:57:30','line','eyJhbGciOiJIUzI1NiJ9.XT6Bj9CVvKIdVrzLSl17ceOKQak-cY786_DjP8v7XKW6HCvWyiQFoyr1p2plhL9CxGGi_eOsAO0qAbLERi9Obk6ywh3EIU4WsxSSJBVSSZv3a0Gy_FdTc0k8t-EIlVuDhjfBt2AeUyam2rKKzgY9wa3JjwjOBjEtDd6fKQPf0yk.OYTuJOGuu24SRVEs7oF_nQpQQkMBDBQhCGNR1JQYFHE','yaVPbh5oz8vHp5kmApc4','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNzQwOSwiaWF0IjoxNTM1MDAzODA5LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.EeLB47KF4YgXmyBLkwaF9kTvTSgleRgDWm6Ics8yO5g','2018-09-22 12:56:50','Bearer',1),(18,'2018-08-23 12:59:38','2018-08-23 12:59:38','line','eyJhbGciOiJIUzI1NiJ9.TQykyBwbLozzImOOj8tL64MbJK6KVCou9Wg8m2GZoTmDavM5oDXxDBjk2M-M6I2I-puJbgkFPEoTQOb9Z2ma_ng1c6bLJkdIx1zz76PaKb7RGM1f36cKO1lQFwIbFQ8f88u7QPZqdykcg2Vl_UbqXFpXxKOzx9d2nuvOupFtY_I.V8Pd2f4wNuCvPChUPyQOML0Kka_k6_Ennv_6kVXYOKs','D72gKtlWlXUBgj75cU2i','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNzUzNywiaWF0IjoxNTM1MDAzOTM3LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.IUXmaF7ioZbRICewGH3poEQzaRit_5pmax_SplvjZho','2018-09-22 12:58:58','Bearer',1),(19,'2018-08-23 13:00:11','2018-08-23 13:00:11','line','eyJhbGciOiJIUzI1NiJ9.cRc6qxtB-OTDGJayYpuO443qNBHgcYAeVJxVWEe6U5UCh1AhM1J_NIGAgrUQfvAkPfMPpe_mSsjYq_vOBCaPy0Fe9JApd9DwZuCCgEMaf2huX9sp_tEpPbuG526fxMi79Fcm_yU4J-bM0tcELTeNoNhtM2IDZNGHeHfdMkjZwek.NLwu_OTsiVCp3akvv1nkHd4dbkJb0vYAUswvD6SidsM','arnXeX9M53u53WK1746T','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNzU3MCwiaWF0IjoxNTM1MDAzOTcwLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.a6L5pZfNYHzMSq19LlWvI9nxXWmwMmQS-GYsUFNJQtI','2018-09-22 12:59:30','Bearer',1),(20,'2018-08-23 13:01:02','2018-08-23 13:01:02','line','eyJhbGciOiJIUzI1NiJ9.fDbf-dzkBV2NerZzXlplw93xu2GnjKqLFryQ0Prc30SL2_84RYOyo4gujasVQ9430qnCRGryUerd2X44j3tIQdbs8d55I5c-ItnEgpUlJcZyGUPcdZrKz2dDssL8NVcBbWeIhURPCZ9AANTKAET5-HC3OwHIaXpP3st07GB9J3Y.FJWl3AuK66pZRhRKVp1VVOTbGCAtDCYcImLK5qMQFTo','dUKCm2rzSrQtn5YDt58k','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNzYyMSwiaWF0IjoxNTM1MDA0MDIxLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.jJ2bBcOtT8Qt7Fl6csH1To5n4gMtwEiy9riXwnVSQy8','2018-09-22 13:00:22','Bearer',1),(21,'2018-08-23 13:01:42','2018-08-23 13:01:42','line','eyJhbGciOiJIUzI1NiJ9.TPA5_0X6wEBrUWIuJjUD41uoK2yLSLjjbTF_Znj596-VLHwZNgHAANJnrzRrgoEbXSMvIKlnMZINYtjTLYhDDzJ1sWMS6x1opVdPiCU0c6BvN2WZ6ld_7IMVHqWejFDxZ8NSYGi4AXb7gZ8ZfYjHHJPusBV4mx8ltpZ7vLzcdq8.EpgOpX5upcyzgpsil7rXYs31Et1DJFZ3Sf1-KqxBKwo','a0Pf7y8EPZ69RQCuXyhP','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNzY2MSwiaWF0IjoxNTM1MDA0MDYxLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.2hN5-2NHvrMXl_WdY3JPL9BCZ7MTW9qh6U14Q2dFU7E','2018-09-22 13:01:02','Bearer',1),(22,'2018-08-23 13:02:12','2018-08-23 13:02:12','line','eyJhbGciOiJIUzI1NiJ9.6sIDsDsCEWjfupM0ehI4ivSb2sIrdiNyLl4z2vZfbb3FpK5MinZF707JkbwtDpb8pIGh5TeerIcqZ0GbiAJoja5F7PNheOvbIiEUJkOKvFH0O9I_mJXtwUsdjabMGybhwzpaxsDW85X_HFkL-EkO6kpPoke0AfBkSyl2fE3B6LU.scCLTX4nyf0KRvi49x_Y_1ON0culTD-Q9iPRq4IH3CM','L8OLegJzT9rlarboejDH','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNzY5MCwiaWF0IjoxNTM1MDA0MDkwLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.VRfGhwYrVIBiRGNieAc7yWYyieZrZA9OgdruSj5zaxE','2018-09-22 13:01:31','Bearer',1),(23,'2018-08-23 13:03:18','2018-08-23 13:03:18','line','eyJhbGciOiJIUzI1NiJ9.B3-E_9E_cVgXrk0AR9jSeQdjK9zfZpFnCkIF8nEVXDqB2f9KtBokpXGmYW3m0BV2eXdlg3qBlaCWEXP07i9RZ8B4whejjVHSfbc3y8Viv5QcaNrVUVvQrBSvJ5ukqr8HUkUpnMt7DFG9A7y_HKbTYNFYprKJNDjgqVw2Jc4wvCg.A0U-r8B7xUAFsaRYUSLP9WrnjSDGvC2cHVClxvN8I5Y','OM6lJKOjlc74eVXgL0Nt','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNzc1NywiaWF0IjoxNTM1MDA0MTU3LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.KchqjvxsoraZ8KG8jePtICVckrZm2j1quj8KYVtcD4o','2018-09-22 13:02:38','Bearer',1),(24,'2018-08-23 13:05:39','2018-08-23 13:05:39','line','eyJhbGciOiJIUzI1NiJ9.F-QiANRmxddUC7OSC-A1ZZNIOdY8WckpWCGCnKUmGSq5E4HNNzr-GXCIjJEhIn4GWBJFELHdEbybEY4WadsHskm5NwjOf4sXZ2MWjx1Ffu1pt1uCOnulE4TH7xuqQ_2asbDee5K_lqkDPEGEF0ArjrtsD4xaNAp6g9ik3kVvuTs.d22O9-s3FMks3AwllX3HhVXHW0m7UG6kvrZnZ8FzZjw','m7a0r0RiPrxQm7WqIy1u','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwNzg5OCwiaWF0IjoxNTM1MDA0Mjk4LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.QBPMNNSdcLDghW9l5jFtyC1B_5vkYEb70A1IFvEF_os','2018-09-22 13:04:59','Bearer',1),(25,'2018-08-23 13:06:17','2018-08-23 13:06:17','amazon','Atza|IwEBIAvxxkkOhZ3gHrMSZzn7VL89XRInIjZV12Zk2wtDVyS0M4Q76SGuR5WUstY4GUVanuK3o7v6sNg3GA7-gli4pyZDN00SUMjJwd_Bs0ka8js959zxi6ssebkSka0_-FLj-iqdTZ82uPc4Zm27S2nr6Ga4SVCwqh9Vy6AeRZTh4n0BDFX6rXu-dx_n9OLucmVsS24944wxpajV9NSYWIpCnAAs-vppgGhEQPOctYqmQEhFodhKxvKPg2KH6c-E8yPVHWOOq2-_-XZhc9nM9iN91X_qYWDZD9ovP3nHwcvDRBUOkxfagZS4M-oUvwILXkohOMJUyoFinjQc6vheppnTbYLZPr9kiskN90tmJIGPy0PxRHsz0Hd7md-DthTc3eBiSj7vSha4AnDDKGfdqhCiqQJsXFQ0AXa13tvIE0jw8h76jy6sS7oiMRGtoB2lUErFhZQPqY16LvZuL9bQVATEfm9JqimkpJ2GBoJ4Dq4I-y0Np53z14BZWraGbWT4K5kb57ZzEQLTnHuDUesprhRe38oKMgmD4cYD59nDGQRIJBPLwgE1LIPQWi2MiwtCCPiTCGY','Atzr|IwEBILFKESzgMGkylPtNOwqWC24Nz8z0y8yDugKbelB7l-uJofkM-FDca1Vr6aRytOGqfin5u0EI9sbXst5nvl0YKhMrn9zd_KRYU50sC-QeUUiLMs5tx3oWSXiS7AoucXUYNLX9YnS8KBO0T_6IFnIJoyZ4t2pynHxzEqvgQvXhsuyjfeDJEFbI8Jxf8Uu5fZsLVgAua-E6MAowW1P5C3YIo7j5CHtSwAOwlQ8tg74FmP6lvVa1XO3GGRTFe0Nzz_n4DjFQxR6p7NSsBANJwmn1ySJjSsU1cBhCwIhUq5LMFp-Qyi2S-Os8zhJEASX8-thjUMpHym29DYEtFKZKswxIm4O7P6Q_1DRAIanQV6rV4F0CNuZCEVv9CYwwrfwMQ2uWPDNkwwzLCCYTZOlEU5HqJwp3tDLUyqQVdlnib1QZ3CZc3P87gs2Hj6AVHFbqdJwqrkWpRLhTrwlUqq0BTl0DLx64KRhUW9sY--7Wv2ESR-TiSP0aw4uLMg4J0GC0P5yHFWIz2kmSPDAUoeUG6GM1wsGr',NULL,'2018-08-23 14:05:37','bearer',2),(26,'2018-08-23 13:06:38','2018-08-23 13:06:38','yahoojp','DD2WE.wdlrfuLwytdYAJAHCXsjYYY.WlrkwTgP_HVrz.zR2UaVY.8G_WJkTTzAfBXqEho1M7EfBGa9cwlzW9IcgS1HBHaVyTKIEmCNs8.8n52YZOLbN6kKYF.1nYcoi1FN9x_h4Hw7E1HzuKxoKJev4j8oDruOh3ZOWlgU8P7mKNZjhYXSI2t3mminpnChDtN0KI0f_L98TRAbUyHppGOoHZo8FIDNqID6z96wNCpcIDR7sHM2FIp3A8qzVLHB4qbSdODK4WeZUjsipPX196JMP1.pGgE8_jTzC6SnfouWjJfelTWAoyLM1Juw2oS3MJEly3Vt0t0n9qBYrKp5kBUhQ0oKJ.GbDCYOF.byZaAMOCI1kaX8BkokkuaCbDJzCl6Neu4_5kgESXC6j6HRGaIGr7RCsHV2E6qdaF2VP7JuSDtbsDI0.ydSkDlWRcv8UUaQD71JGla3h1eT9AL3htObuDdUk794Cd4iTrpqPaWL_R4zA7TwJuxejsz78S9Yg.xyAuW.RxT7u9t.gNw4qA6kjOVCtkot_8K.w.Kn8KM_HejPO0bmOi7Y8YZk4C36MjjPayEngPdknaOLTd9ktG6vI8q9S3Us22gDj5fO1hWAVKxhedB4qVdVx482NcEtoVpnTqDYF.shWqFj5NAIS_Eb6Vjm4Jlmfah4kBoNy89retyoIEHkimPPenQnzYwVbj3D6pLM9Ul2fPKmOjwTuSjNa2A9zpotrPluuhnxqYIRMNQ.TxgXCi0xmr6Er1orlDrJc_b15m0GgAwa7GyQYhQjf5F.weQbqL5ZkYx0fnXVAt3hXUsjbkZs4KqP1Z7X9oy.u_','n6x.TRNnPp4yr65dyKfdDtiBvkTwbntwx_B22XIqxGujUAq5IwlAx2..JPT.eFqs5i_HNnca','eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjBjYzE3NWI5YzBmMWI2YTgzMWMzOTllMjY5NzcyNjYxIn0.eyJpc3MiOiJodHRwczpcL1wvYXV0aC5sb2dpbi55YWhvby5jby5qcFwveWNvbm5lY3RcL3YyIiwic3ViIjoiRU9HS0lVR09GNVRaWlRGS1o1Rkk3UEsyM0EiLCJhdWQiOlsiZGowMGFpWnBQWGRMZDNGbU1FVm1OMDFWYnlaelBXTnZibk4xYldWeWMyVmpjbVYwSm5nOU4yVS0iXSwiZXhwIjoxNTM3NDIzNTU3LCJpYXQiOjE1MzUwMDQzNTcsImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNTM1MDA0MzU0LCJhdF9oYXNoIjoiNWxhaUN1QVRtY3NIc2dLWmo4RXhmdyJ9.cU2HVr8hn2N0MiSdLw8YD_zjGrOaO4lAGkwbIkcTrXm51i2gOuwVSjkMEXk05ocia-7m6YoKg19dnow_tPX3G48znmC7EC5Zl3SomBE3NYFLDsCKDcXoCzbiufc1j6miSF6895jKJex8tbDtP50namuW4Xf8bxvjNIrfcsQa4ju8gwAIsYPVPZDTVxFniw4ypoQJQsdyRMihbmD44jxW_HGNuWrsNf5vwJbfdwh7oX8Vhj1Q3dRsO5n3Rw3-WHyOJb9OUuZuXnfy6thC-GyrtAZh0lODkx40aGXLT-dXHLbLJV7w8ZYxHn04IIRQUeJHLXc5kTy2LAQJBNk4kUoDtw','2018-08-23 14:05:58','Bearer',3),(27,'2018-08-23 13:34:25','2018-08-23 13:34:25','line','eyJhbGciOiJIUzI1NiJ9.abtcc1YH0hgKd4l1rrlAeGGtOLvUy7YA1tRHqhtLQbvq7G_99X96NItLoOX8My9N-1qUy16AfN8raVZ-As63BptGFmTqZ8-6IZbAb_-JLvRiqCwUT9zD1sL9SoFTXB6ocTqZdPhcwJGoqwziSg6e2Ula_mHzjD-bz2rz-61JI7U.Lb7nHtGq4tJMPdbdqUCrNwSIH87g4lyfK03d3t0Eeno','6DZGktXBM6oDbA3tEbco','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwOTYyNCwiaWF0IjoxNTM1MDA2MDI0LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.BznwrYyxGYqhTvrXpi9gW-khkXgxSvfCa2oPhiyd_tU','2018-09-22 13:33:45','Bearer',1),(28,'2018-08-23 13:34:32','2018-08-23 13:34:32','line','eyJhbGciOiJIUzI1NiJ9.z18z04iGImClaiaS-zTWZHzeZBnEGufuqr_rkHyk4SwESIIfkIoOi9EltecTMbCw3KeZYNsofOmf4IskoEoObZgVkDHXnNR4XFWqjpbMfX4GouFHKoIrSPBrw9JAG56RHXor3AF924WSbp1DcNRiDKs_6rKvaK6mHVMVVi_dFms.6UFpQSvKOUMkckWFHozveaw8saEixR_w8urGrX872ks','Ffy4J30ShibuSp8fuYto','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAwOTYzMSwiaWF0IjoxNTM1MDA2MDMxLCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.1FZNlv4Ru7Ty1_XT7Jl49W48YAFga45oQWmWIaAybZo','2018-09-22 13:33:52','Bearer',1),(29,'2018-08-23 13:58:10','2018-08-23 13:58:10','yahoojp','yP4UyrM0ioe8NcYoEO3Jj5UxxHKBY8BDMDAE.5StMd8AeOqZpsbJOWKXTV.bx2i0M55CjVVMMcfBv7jaSlFp_65o2YX19BBCfK.3ZxysR.dxSnvtB41X7w6Kj6Autt73InyONSYNwR4Gfhg9yV3AUg4FIjJH9YwsDyi_x7hpM5CaPg0B_nG.sHkcpE6QK9nGdIzR6PQLot6z.z.wJL49oEPmVTPIw2fE8t.oHvbYulHcADz6CEzLq6M5tqAq0p2XDMNGjnPHpaYj94JMsVQovH_FqeVUIIRXSAd1uPFfD2RGlS45caDQq4lj1Pifv8J1k0MpIhSUgEHpPOyLAaFSEz188I8CY.j.APJLNiCRx5BgkPwM138Q6tS.e6yGs024lZR0p5FT6sJ4Qd_xopdy_39x237_b3fOJuGQTVj72km.F8F0c7g3FF2iVxtCUKSdtyxZaU1FGZfaICilGD3RZn_CuZK_sLDZ4tYnXgV0um1FaFmur3yTtwnKDlAWKMU3cHGjutPf1F6TiMldMJRdf2VX9Kv5HopKETzn2Jm.K6NUJoUqkH2MvYEfDWZRaRKB.d0A.aDBlsoK9.wlj6PvPiLGVy.BqbDrKoc98aNb00bjFzLCRfYc.Bkm0mrA3E2aFeANRyFp2ngeIbsgPejHXmKRqgj7lmEf83mUcyqpvEGnS1kQqA_BWoyLKylO3u8EENTToryUD7lhGzpiRBk8pOq6C9njhT8ijTMSRsWXeKrcAQGcv1WxDR3uMJ6CtDeyiHNUnVfvmfPycMdNK48ZvFKH9WLTbpPbe2Aeq_g4IVxYL6uYLXmaCu6bazpa4Wihok61','n6x.TRNnPp4yr65dyKfdDtiBvkTwbntwx_B22XIqxGujUAq5IwlAx2..JPT.eFqs5i_HNnca','eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjBjYzE3NWI5YzBmMWI2YTgzMWMzOTllMjY5NzcyNjYxIn0.eyJpc3MiOiJodHRwczpcL1wvYXV0aC5sb2dpbi55YWhvby5jby5qcFwveWNvbm5lY3RcL3YyIiwic3ViIjoiRU9HS0lVR09GNVRaWlRGS1o1Rkk3UEsyM0EiLCJhdWQiOlsiZGowMGFpWnBQWGRMZDNGbU1FVm1OMDFWYnlaelBXTnZibk4xYldWeWMyVmpjbVYwSm5nOU4yVS0iXSwiZXhwIjoxNTM3NDI2NjQ4LCJpYXQiOjE1MzUwMDc0NDgsImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNTM1MDA3NDQ1LCJhdF9oYXNoIjoicE90b1k5bjhoVWxyaG1HbHF1a2hKZyJ9.G5FHIh1bXm9UwJg9GJj4InDqvse-NiXRaOOj4HM_xxb_E0MhJLkAsI_KcesZ3XwKe2IOOL4jxcMSO1ACLBh_ZvBBjftBOdY5mCZg2AvU1hMhYMAQCinNFAM-TELPemsORkfZXx6u1UIatmZNJx3p3A2Faj9HxECLrT_tDlEtrXAgQGt_lcbTwaeTeZ0sCI7-WMo1nFFaVPXUlPA-szEmq3n01OXiIcYtNlymzQxBwFlodw6A0UP_5heuVr5URSS-RBYRrAGUufsdlwORRiVRXoZnsJf-GAknvANovgx4dv10_q_-hL2Lcu-Xr08NrPMtub3n3a4oHMoZnUExN-1i8g','2018-08-23 14:57:30','Bearer',3),(30,'2018-08-23 14:00:40','2018-08-23 14:00:40','line','eyJhbGciOiJIUzI1NiJ9.iT6MbMHKdkgbffkA1LIAtxo8jdE5BmzDhjhOfUz-iDqCykIUWPvRduHsvS5bRD0zwgToa_8O1GmeuhlJw9badm5T4VaxCc8VFHtmKz5moj52Mo9wNd2Wwd-iD6ghETqWRyHUe0UKfWBKmCbICdtPbrK0uJ7wMhMIAPWllklvhSQ.Bwhyd3YuSOyajaw_XsdrVEyEn6Jvz7VQPr_imb8whMU','YGqWN4l7oJIwV5COP7Ok','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAxMTE5OSwiaWF0IjoxNTM1MDA3NTk5LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.jADipdXFyKmLUy4gaY88X98aba-yaZ9u5-n17pP3tbc','2018-09-22 14:00:00','Bearer',1),(31,'2018-08-23 14:56:57','2018-08-23 14:56:57','amazon','Atza|IwEBIL014UPthkXpI_sIyhvbgm7x82G9ifplAN4kpUwscJmUHmfdL8KitxIXE7iL8lX67KW6uJhWjMqzyTzDKclOFm7g8CXXZNl2dNS4pSSegl0EutJXxpbDR20G7u9SNdpJSwdKSwvzBvLKsqeehK-zMDjxHSFguVsZSq5K2dOJ0zPYEg55GJCUxw3dd3eMoHZyERNPgHdPrasyffrVpFyhdCzEB2LUPlXfLeSKfjWo-x7rWbGPIFvddb1Wo7U7Mq7Ot02TJZia179tx3gljNXvrRYkBx1GjQq_cSXHoXM7sWMlC1Jmv-NYFOyWZemXovuoszh3OMk1F1I_0STqNBaaA9vORlnAZ7Xb5UDX4FD9nyh1YBAinqKNHCa8GZVBJka2QQzD8fd7EEI1mG1u3kXoN2WvaINTQ5hDWwYUtr9wRuNLPe16vfRyJEpfDW5DPPuug7eUskmyBbgU9-yNU1GEVQDiufSh2dgzlVGG-o6Tzq4roanxt7aEv3dkXlsOpQtHgFWAD9qfuOXyRx5hZQM70KxIdiH5tTnHH6Vsate8SYsxQS0QA1hIIajh66vAJTTBX2k','Atzr|IwEBIN0PMOKoLUJm3lz3At9sD7woaRuSDVJyF6iX6mQnGi-Ashnv4ipBC1-y3vXlE___NidoN3YIGW8pHgGSERevjolOq8aJiupfsXqo2leBUBarIHglDcVbVI75BldMjTgnTTW77oVvwrUpehVAjNJR-GG45U3-dBPGGWk8pJTfk6P4-DaC_hCq3IyKuaXPRO9FkuSBk7kANDz5m_01eDxNQQNemS9aa_nqju-_xK-LF60yLDRTV8-peeg9dlsx3koHrZFQiKv1cgxZTcw8rYkySbhCzZ0FwTOc5pWZ2U6rUQMx9rDLKwlqoC3sszcZ_-zEkKmlXegm-wRJtvJ53rRwLjtBOSHM7dEJQMOGMeQHF_f4MGO09r2QU313AhEzCStxHaVIZZ94hb5QMVxxkWG7GrNcA7V33atgL9oBHzD5OevbLdLN_8wA-RNOsQ8Lwi21wip6jncz1T0Ixn-KW2S1jCdPrUbdpRQzTYQJzsQwp-zSeOgZWETOv8kmIw271vkxuY5yxVBPmVaGGsB2dZvj4LOJ',NULL,'2018-08-23 15:56:17','bearer',2),(32,'2018-08-23 15:23:02','2018-08-23 15:23:02','yahoojp','2BlHOdILipdV61_eCI_Pk_vEJjDQSr3TnqhVAdNoYmzf3sxH8vOP.XKkeJQe_3ogWfbJfVNoutHsw7_1aiVTSVGEZ7NF0EjVhVaNkLQaQOR8_qMvh_z4lSrHVsqA.aKLVB_2pbZY5iEdomMuo_4J5NK6p7lC8Oc4AHsyj7o5d8kk9glPvYm4s2fgXR9wONNUoUj7kofhYRIUSCrJVYMck0FOnZ6L0QXZfh2uDJ_L5lxZhOqmMbg_fW.1444kE17aD_RNKBrOxr7lkOz0wOLxmw9Qe.yPKB2yzFOH4xbhLp59e8PsQvkwyl0QKxMHqL8wAZJOOkpLstI7UN1mxUugEgg8JuRUEek7pNO7rdCw3tN.Qwnxp3zqZ1pxAi76H44PbmuGiscQDNhDW9s7bkzX9v68CEK0T7s8Cw_6_.Muri_c5icU8Bn0WxLZRPBIi49fmP87_u1HlPM8.vi6X7UgY8hqppzjv_A1rLRQZ6L0XNBX08yx9.X7pqCaSgsp2tSLOWA3BH1i6.rXgvLlnpRqKMQ7uGogQsbj461m_bPbmK54kwy5CgmmyvNEsP60P8JZ7FUjJU3rkCIrP6XKZpHw990Kh9copf_A4jCT9V3cXgj7dU0AQQkXxo8NiSMerUqWKHwHP5iOSfVkkFeyroV1UocwSmvnBt7bkWH.fU75RuwAeNE5E0AbhPe78Xa4tU2ZYH0psKLFOOkqGOp_9rWFtQajt0TcR1GvOwIU_G1CqPUfKYHUms5ZVh3aljPJsGSiBa_N47Z9vDCphqWlB6E9AyQqcNBR_UxiWg6.atBoQbTsgS1bMLBIhkoJ98s4qvffhRn_','n6x.TRNnPp4yr65dyKfdDtiBvkTwbntwx_B22XIqxGujUAq5IwlAx2..JPT.eFqs5i_HNnca','eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjBjYzE3NWI5YzBmMWI2YTgzMWMzOTllMjY5NzcyNjYxIn0.eyJpc3MiOiJodHRwczpcL1wvYXV0aC5sb2dpbi55YWhvby5jby5qcFwveWNvbm5lY3RcL3YyIiwic3ViIjoiRU9HS0lVR09GNVRaWlRGS1o1Rkk3UEsyM0EiLCJhdWQiOlsiZGowMGFpWnBQWGRMZDNGbU1FVm1OMDFWYnlaelBXTnZibk4xYldWeWMyVmpjbVYwSm5nOU4yVS0iXSwiZXhwIjoxNTM3NDMxNzQxLCJpYXQiOjE1MzUwMTI1NDEsImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNTM1MDEyNTM4LCJhdF9oYXNoIjoiWVFPckdIQTRxQ3J4LXpmbXVCa3lOdyJ9.eVbimZbtVWO2eTNGudDhu4tfeEOQbpqvKxrq2sfmurrlufpK2RrLTEtafzNGjvS4Pbu9IRJAOWpPaD_mzTtV1MA6PaLkT026GTAk3foOn7CsrTCGapeRRrxNYL4TkLZ4AnoDsxmJtJh6YE_SDOqi9-8R-Z1I5vZOP3H0NBEH7s9jHhMESksQC79j-KVLzHtuqbctWUIM6rcgm_sIviqGmsxgX40G-lx1cD6JRagjRTL-4hJPo9faSDjUTyrqJxM2OlZMAnZSEI_B54m6IR9kEDH614diSFk54lRhfCwP3yn77tQN_Xg2ec8TwerTmXzWeqBCPGsBd6mku7sCdHMO9A','2018-08-23 16:22:22','Bearer',3),(33,'2018-08-23 15:23:09','2018-08-23 15:23:09','line','eyJhbGciOiJIUzI1NiJ9.bOMsRSyxiM7D8Jp9dFuWPTol4IVtGpAI6MhI_0rCg78zP4Q4ai_T_vaVwaIWQRK83stx4X2zC1jgR3ENQpNgd_x7n6HsH5KJpnDvHyp8bC6YToCx8mvcqyuOzOynZ1iRpVaIsl6G7LIsyKfmzPtFKnusQMEvunKpbaMCtqlurRw.-kdztzCL_-wo0NwG7K8L_c-vqJYASHbz4JWBcYAYf2Y','0E8pZE8osmZyFqXwsbqL','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAxNjE0NywiaWF0IjoxNTM1MDEyNTQ3LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.uzz9DYiLO1ngl59aL-GlpFF0isCsdUdTEno6bWkcb88','2018-09-22 15:22:29','Bearer',1),(34,'2018-08-23 15:23:59','2018-08-23 15:23:59','line','eyJhbGciOiJIUzI1NiJ9.Ip3x4CsBy2xn5pCsGuC9DvIQHggW43hWAOxgpgvzb1fRGhYv8VEFnhpzW86fFQDI8pRCURSzlR94YF1eztIa8nBHkF05cKUTU02jU11uTkrs1ystSdu5nM0HxirWglyXIRkiEWqdNZevQ_OSNOo0j5QnEoOurWK6iu_wslvtMAc.sBXjuX7SEQOi6pkJNkeYp1Fv-3Vd3GXc6jnSHS-kfvA','FqiGH897UeOGtvXIHCxP','eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwic3ViIjoiVTA1ODMzNjdmNzU3ZDE0MzM3YTVjMTg0YzI0ZjBmNWYxIiwiYXVkIjoiMTYwMDI4ODA1NSIsImV4cCI6MTUzNTAxNjE5OCwiaWF0IjoxNTM1MDEyNTk4LCJuYW1lIjoiYmFuZ2JhbmciLCJwaWN0dXJlIjoiaHR0cHM6Ly9wcm9maWxlLmxpbmUtc2Nkbi5uZXQvMGhHNHVrSW9YWkdCdElFalVnQ3ZkblRIUlhGbllfUEI1VE1IMVJlejBVVGk0eWNBb2FjeVlDZWpnWEZYd3hLMVpPSUhFQ2UyVVJGSDh4In0.wW3WMqq83ZaiOUgyBPJzSB4DfFdBA9IlgIJd_hpPb5Q','2018-09-22 15:23:19','Bearer',1),(35,'2018-08-23 16:34:13','2018-08-23 16:34:13','yahoojp','2Mn.mfUa5I2Zv7ERGJGX3iSvN32HMB6nDJKMeKIDe.nr46g15AhAAjoh6kDi3OIcSh.aPjcVU59DHwBGdwqVD_O_dAcPtkCCtbzJENJOIi4dJZq6WRCZzUTSFs6.EBo9Nai3ZXO1XPpVEmxWm76gyDEfGBQZPs.Mil_WFQ7Jj4PVknQ7O0zr3PDXHQI6lvzQrZCqEmlgsDeJYvQFpTveVNZKspFdiryyuVVSSOomUbHu.UKby.3peniM8jKt6ACMGBIUzfuuS7cgh1d_iLZt_p0ONtqQiQaQq2uKUNPvjUcEnBvwCAlmOh6tT_kV3QjAfscH3odDYYtBjpSQI7fP58eu.GsPQlwOphrQRpWzTUbbnb_YZsG8MZ8fFSe5lxmAJheyyFISy0Upzt49ICkJBiDdMX1jbptCGH1nsTTpF5O8UwMJfLDwtA2Y.IMt1RzoAhO5d9s916WJtK.couL4R.tmJCYXuqiTnN10mxpEKcMNOsVJH72QH1qP_z6BrD98YaqwocoDVYQFSau14m4ycxRAk9BCyq_L5BE0q8Gmf7NZe9N83KNnGc.4oy55LUTVVwsPM8dNIaAjtw3mKmwstkmTFWlIbV.CQki2PCbVcgAfPCtekY.zMA5zr5oO89WhywKcXcdxea_1ao4akdM6ltfg7yoErU.VaxW7tl0srbyZX.qVfbdM0Pd03jtGvHaVGSpCW9USCbgUog9xo4zJjNfuNWuncBApiicRAK65VoNvGS.AmSLFBwf7fUrmeI7sIsZSh6hKPhiORMVJLEUQbQuR99toflFP337cGU4M0kG4kHv0u1E8RW7EFCQq05IYjVEP','n6x.TRNnPp4yr65dyKfdDtiBvkTwbntwx_B22XIqxGujUAq5IwlAx2..JPT.eFqs5i_HNnca','eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjBjYzE3NWI5YzBmMWI2YTgzMWMzOTllMjY5NzcyNjYxIn0.eyJpc3MiOiJodHRwczpcL1wvYXV0aC5sb2dpbi55YWhvby5jby5qcFwveWNvbm5lY3RcL3YyIiwic3ViIjoiRU9HS0lVR09GNVRaWlRGS1o1Rkk3UEsyM0EiLCJhdWQiOlsiZGowMGFpWnBQWGRMZDNGbU1FVm1OMDFWYnlaelBXTnZibk4xYldWeWMyVmpjbVYwSm5nOU4yVS0iXSwiZXhwIjoxNTM3NDM2MDExLCJpYXQiOjE1MzUwMTY4MTEsImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNTM1MDE2ODA4LCJhdF9oYXNoIjoid0hLLWNleTR6bjJRQ1BCTnAwNUU0dyJ9.fa-IiDJ44ZTv9hpxVFyFNu_TAF5gw2qz7TX1aesHcCNEEC-VCYZYJfczqR2491TpF4uW4yCrFdHYuvcNJalB8rEQjzh5KLrr4ofZHShk9f2_PGGK5SOrf96p-VQdhPpD_7XLlouyG2mbkv49gOgat9p5JVATvp3imSMOmJhAnFIZBfiCb27NxfyIVaDHtM_eI_sarNah0zrkQoLKWOqxGwCy786EQXfQ-l-BT1ov2ZwRMuL66FsAH4Zs4FLQAHXmtXTXqrPPJ6HKyY0tl82rwIfpi0oI5ROVneUsN6HxiFmIJlyL3TygCiH5VviSacldzmUO8sm7IeyONtO6izYelg','2018-08-23 17:33:33','Bearer',3),(36,'2018-08-23 16:40:39','2018-08-23 16:40:39','amazon','Atza|IwEBILh2lZEEecN8CmhaJ6yKi8-VvAct8Ensu7rGHXXDTVLq9ijSYs_G3EPi6XLWXxvW0_EzZyW0qOmeoA0t0koJg8dlmIiek30cCvdbGeKbgMpNZ2HNRra-lDqOKthTd2t6W1LyGciuXCkzzbBzs-YuzffBweucmrSAHzbiKk6bpWSXXQe4WzfJv3Etu34HbViomqnin1wiox3k5vpBrpY0Ln8C7uruUul5_X-yzd8a6FS_-I6Xad53UdVCjA037L9Xnk11AA62G9JX20PL1RPTpqJ07OzSa1Z6ysv9bvaCObFXE1aEw9luQ1v_tEmqT09SZ8fZXRW45AHRDv3S4PN5R6hM5P-dD0vhKhLoGDL_xFWdmgaaqAuDXIzyP2d_2eXvstQpAgagtYCcJxmsA11HdIHp7C7AiFO6N4Y9fdyms975PQZjsrt0K408q3J6NqXOFeGw-djt7xvHfTcZ6Ua6RXHd8CnpXxQ7IYQuWr7DRyr8YHGczcIK1T_ARspHEbPtwcTGqxtl9sqWfT3lyoV4tB1G2VcfeNnr6LXRzT-NnwN2ooxp3SB7-9C4yg3HKDWqq3Q','Atzr|IwEBIGFN95-81WWQKQkd_kG7UegzRQh7ivRBe0EVYInSJGG7-Anx1xd91scyJ_T1hX67wOL8LGhrmbfJvwpIhYx6un_M_1Ez-B0ZoRSNEKp1bK1aW_BuLx3DdiFFzrJQHVIpyzBbENBcAydDiyMB2hCbDHDpeASqxaC_j6XuRw77Gr262Gmnl1aM71KEdwKB_Y-bW2a7t5qU2fD3jChkp4a42E3a4AldqXZZv1cYiRlANQe6XzUdJsK346nxQfumWRiDeQAIePkqgrIw8ohdnPX7Ne8cyLa0jTZ0tShLus92Q71eEq26PTF4WQ3C_hUqCdq4lfyxYIVHrk1Rfql03mXtDhtuFPnXPN7hHjbCTyNrOMuuOEhYcQ1_CzvYoQdrRmkF9nlVvK7JAFz1jlHxZ4DSa5c43rVemYPZZU8UWsVUwR-NgBb3Kd9D1pv90cy6Fb1CPJSB4z1tb2_dyD74cy75SZKtP_K7WN3Vr56kSA8l0VmWHE5phs8Ng4P2XGs-ZajKI2tIW74RJ5qciafxksER99xU',NULL,'2018-08-23 17:39:59','bearer',2);
/*!40000 ALTER TABLE `tokens` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `_id` int(11) NOT NULL AUTO_INCREMENT,
  `created_at` datetime DEFAULT NULL,
  `modified_at` datetime DEFAULT NULL,
  `pk` varchar(255) NOT NULL,
  `last_login` datetime DEFAULT NULL,
  `last_provider` varchar(15) DEFAULT NULL,
  `login_count` int(11) DEFAULT NULL,
  `deleted` tinyint(1) DEFAULT NULL,
  `app_id` int(11) NOT NULL,
  PRIMARY KEY (`_id`),
  UNIQUE KEY `pk` (`pk`),
  KEY `app_id` (`app_id`),
  CONSTRAINT `users_ibfk_1` FOREIGN KEY (`app_id`) REFERENCES `apps` (`_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (2,'2018-08-23 13:53:22','2018-08-23 14:00:41','tjeubaoit','2018-08-23 14:00:00','line',4,0,3);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-08-23 17:44:19
