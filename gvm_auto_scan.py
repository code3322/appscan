#!/usr/bin/env python
# encoding: utf-8

# -------------------------------------------------------------------------
# 头文件
import os
import datetime
import logging
import pymysql
import json
import os
import time
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print
from gvm.xml import GvmError


# -------------------------------------------------------------------------
# 全局变量
# 运行时日志文件
log_file = 'error.log'

# Mysql数据库信息
MysqlHost = '127.0.0.1'
MysqlUser = 'root'
MysqlPwd = '000000'
MysqlDBName = 'appscan'

# openvas(GVM)登录账号密码
GVM_USER = 'admin'
GVM_PWD = 'admin'

# Scan config ID(扫描配置ID, 用系统的比较好, 自己配的话需要过滤过多的CVE)
SCAN_CONFIG_ID = 'daba56c8-73ec-11df-a475-002264764cea'

# scanner ID(扫描器ID, 暂时无法深入理解)
DEFUALT_SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73'
CVE_SCANNER_ID = '6acd0832-df90-11e4-b9d5-28d24461215b'

# 过滤ID(用于过滤结果的ID, 在页面上比较好配置, 需要在周期性的维护, 基本result结果过滤(CVE))
FILTER_ID = 'a7b78b0e-d81c-4b0a-a21f-47f38834b2c8'

# 扫描的临时数据, 扫描完成后需要删除
scan_temp = {}

# 要扫描的ip
IP_LIST = 'ip_list.txt'


# -------------------------------------------------------------------------
# 类、函数声明与定义
def sql_exec(sql=None, return_data=False):
	'''执行mysql 语句'''
	conn = pymysql.connect(host=MysqlHost, user=MysqlUser, passwd=MysqlPwd, db=MysqlDBName, port=3305, charset="utf8",
						   connect_timeout=10)
	cursor = conn.cursor()
	cursor.execute(sql)
	conn.commit()

	data = cursor.fetchall()
	if return_data:
		return data
	else:
		pass

	conn.close()

def set_log_level(log_level = logging.DEBUG):
	'''设置日志记录级别'''
	# 设置日志记录级别
	logger = logging.getLogger()
	logger.setLevel(log_level)
	handler = logging.FileHandler(log_file, mode='a+')
	handler.setLevel(log_level)
	formatter = logging.Formatter('%(asctime)s - %(filename)s - [line:%(lineno)d]  -  %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	return logger


def login_gvm(gvm_user=None, gvm_pwd=None):
	'''登录gvm并实例化一对象'''
	connection = UnixSocketConnection()
	transform = EtreeTransform()

	with Gmp(connection=connection, transform=transform) as gmp:
		gmp.authenticate(gvm_user, gvm_pwd)

	return gmp


def create_scan_target_ports(gvm_obj=None, target_name=None, ips=None, port_list='1-65535'):
	'''创建一个要扫描的ip或ips, 注意ips为列表'''

	# 创建一个端口扫描列表
	port_ret = gvm_obj.create_port_list(name=target_name, port_range=port_list)
	if "Port list exists already" == ''.join(port_ret.xpath('//@status_text')[0]):
		return False
	else:
		scan_temp['portlist_id'] = port_ret.xpath('//@id')[0]

	# 创建一个扫描目标
	ips_temp = []
	ips_temp.append(ips)

	# 创建一个扫描目标
	target_ret = gvm_obj.create_target(name=target_name, hosts=ips_temp, port_list_id=port_ret.xpath('//@id')[0])
	if "Target exists already" == ''.join(target_ret.xpath('//@status_text')[0]):
		return False
	else:
		scan_temp['target_id'] = target_ret.xpath('//@id')[0]

	return True


def create_task_start(gvm_obj=None, task_name=None, config_id=None, target_id=None, scanner_id=None):
	'''创建扫描任务,并执行扫描'''
	# 创建一个扫描任务
	task_ret = gvm_obj.create_task(name=task_name, config_id=config_id, target_id=target_id, scanner_id=scanner_id)
	scan_temp['task_id'] = task_ret.xpath('//@id')[0]

	# 执行任务的扫描
	if "OK, resource created" == ''.join(task_ret.xpath('//@status_text')[0]):
		start_ret = gvm_obj.start_task(scan_temp['task_id'])
		if "OK, request submitted" == ''.join(start_ret.xpath('//@status_text')[0]):
			#print(type(start_ret))
			#pretty_print(start_ret)
			scan_temp['report_id'] = start_ret.xpath('/start_task_response/report_id/text()')[0]
			return True
		else:
			logging.error('start task fail', exc_info=True)
			return  False
	else:
		logging.error('create task fail', exc_info=True)
		return False


# -------------------------------------------------------------------------
# 主函数
if __name__ == '__main__':
	'''程序运行时的msg'''
	starttime = datetime.datetime.now()
	print('-------------------------------------------------------------------------')
	print('程序将很快执行，现在时间是:', starttime.strftime('%Y-%m-%d %H:%M:%S'))
	print('如遇异常，请查看当前目录下的日志文件 error.log')
	print('程序正在运行, 请稍等.....')
	print('')

	#设置日志记录级别
	logger = set_log_level(log_level=logging.DEBUG)

	#程序核心部分
	try:
		# 扫描的逻辑, 首先创建一个扫描target(也就是要扫的ip), 然后创建一个端口列表(扫描哪些端口), 然后再选择scan_configs中的一个配置(要用哪些cve去扫描), 最后再选择一个scanner, 然后创建一个task, 开始即可, 然后获取task状态, 扫描结束后获取结果并执行白名单过滤, 最后输出结果
		gmp = login_gvm(GVM_USER, GVM_PWD)

		# 从本地文件读取ip进行扫描
		if os.path.exists(IP_LIST):
			with open(IP_LIST, 'r') as hScan:
				for line in hScan:
					scan_ip = line.strip()
					scan_temp['ip'] = scan_ip
					bResult = create_scan_target_ports(gmp, target_name=scan_ip, ips=scan_ip)
					# 创建任务并执行
					if bResult and scan_temp:
						create_task_start(gvm_obj=gmp, task_name=scan_ip, config_id=SCAN_CONFIG_ID, target_id=scan_temp['target_id'], scanner_id=DEFUALT_SCANNER_ID)
					else:
						logger.error('create task fail', exc_info=True)
						continue

					with open('task_result.txt', 'a+') as hFile:
						hFile.write(json.dumps(scan_temp) + '\n')
		hFile.close()

	except GvmError as e:
		logger.error(str(e), exc_info=True)


	'''程序运行结束，并显示运行了多久'''
	print ('')
	endtime = datetime.datetime.now()
	seconds = (endtime - starttime).seconds
	print ('程序执行完成，一共花费了 %d 秒' % (seconds))
	print ('-------------------------------------------------------------------------')