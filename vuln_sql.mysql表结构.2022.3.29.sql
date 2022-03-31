DROP TABLE IF EXISTS `bug_desc`;

CREATE TABLE `bug_desc` (
  `ID` int(10) unsigned NOT NULL auto_increment,
  `Host` varchar(255) default NULL,				/*主机(ip)*/
  `VulnName` varchar(1024) default NULL,			/*漏洞名称(应用名称)*/
  `Port` varchar(255) default NULL,				/*关联端口*/
  `VulnSeverity` varchar(255) default NULL,		/*漏洞级别*/
  `VulnScore` varchar(255) default NULL,			/*漏洞评分*/
  `VulnQOD` varchar(255) default NULL,			/*漏洞QOD*/
  `VulnDesc` varchar(2048) default NULL,			/*漏洞细节*/
  `VulnDescTag` varchar(10000) default NULL,		/*漏洞更详细的细节*/
  `CreateTime` datetime DEFAULT current_timestamp,		/*插入时默认填写当前时间*/
  `UpdateTime` datetime default current_timestamp,		/*插入时默认填写当前时间*/
  `Project` varchar(255) default NULL,			/*项目名称*/
  `ProjUser` varchar(255) default NULL,			/*项目关联的负责人*/
  `Flags` int(5) default NULL,					/*处理标记, 0为新数据，1为处理当中, 2为处理完成*/
  PRIMARY KEY  (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;