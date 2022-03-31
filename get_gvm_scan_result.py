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
from pymysql.converters import escape_string

# -------------------------------------------------------------------------
# 全局变量
# 运行时日志文件
log_file = 'error.log'

# Mysql数据库信息
MysqlHost = '127.0.0.1'
MysqlUser = 'root'
MysqlPwd = '000000'
MysqlDBName = 'gvm'

# openvas(GVM)登录账号密码
GVM_USER = 'admin'
GVM_PWD = 'admin'

# task_result.txt 扫描时产生的任务信息,通过此文件中的信息提取结果
TASK_RET = 'task_result.txt'
task_tmp_file = 'task_tmp.txt'

# 过滤ID(用于过滤结果的ID, 在页面上比较好配置, 需要在周期性的维护, 基本result结果过滤(CVE))
FILTER_ID = 'a7b78b0e-d81c-4b0a-a21f-47f38834b2c8'

# -------------------------------------------------------------------------
# 类、函数声明与定义
def sql_exec(sql=None, return_data=False):
	'''执行mysql 语句'''
	conn = pymysql.connect(host=MysqlHost, user=MysqlUser, passwd=MysqlPwd, db=MysqlDBName, port=3306, charset="utf8",
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

def get_scan_result(gvm_obj=None, task_id=None, report_id=None):
	# 分析扫描完成的任务结果
	task_state_ret = gvm_obj.get_task(task_id=task_id)
	if "Done" == ''.join(task_state_ret.xpath("/get_tasks_response/task/status/text()")):
		print('scan done')
		report_ret = gvm_obj.get_report(report_id=report_id, filter_id=FILTER_ID)

		# 获取一共有多少条数据
		vuln_list = int(report_ret.xpath('//result_count/filtered[1]/text()')[0])
		vuln_list += 1

		# 获取本报告的主机的ip
		scan_ip = str(report_ret.xpath('/get_reports_response/report/task/name/text()')[0])
		print('Host is: %s' % scan_ip)
		print('-----------------------------')
		print()

		i = 1
		while i < vuln_list:
			# 漏洞的名称
			name_path_temp = "//results/result[%d]/name/text()"
			name_path = name_path_temp % (i)
			vuln_name = str(report_ret.xpath(name_path)[0])

			# 漏洞对应的端口
			port_path_temp = "//results/result[%d]/port/text()"
			port_path = port_path_temp % (i)
			vuln_port = str(report_ret.xpath(port_path)[0])

			# 漏洞安全等级
			bug_level_temp = "//results/result[%d]/threat/text()"
			bug_level = bug_level_temp % (i)
			vuln_level = str(report_ret.xpath(bug_level)[0])

			# 漏洞的评分
			bug_score_temp = "//results/result[%d]/severity/text()"
			bug_score = bug_score_temp % (i)
			vuln_score = str(report_ret.xpath(bug_score)[0])

			# 扫描QOD, 检测质量, 描述漏洞检测的可靠性
			bug_qod_temp = "//results/result[%d]/qod/value/text()"
			bug_qod = bug_qod_temp % (i)
			vuln_qod =  str(report_ret.xpath(bug_qod)[0])

			# 漏洞细节
			desc_path_temp = "//results/result[%d]/description/text()"
			desc_path = desc_path_temp % (i)
			vuln_desc_tmp = report_ret.xpath(desc_path)
			if vuln_desc_tmp:
				vuln_desc = str(vuln_desc_tmp[0])
			else:
				vuln_desc = "no data"

			# 漏洞更详细的细节
			desc_tag_temp = "//results/result[%d]/nvt/tags/text()"
			desc_tag = desc_tag_temp % (i)
			vuln_desc_tag = str(report_ret.xpath(desc_tag)[0])

			# 保存结果到mysql
			# 判断数据是否已经在数据库中了
			detect_data_isnew_tmp = "select count(*) from bug_desc where host='%s' and port='%s' and vulnname='%s'"
			detect_sql = detect_data_isnew_tmp % (scan_ip, escape_string(vuln_port), escape_string(vuln_name))
			detect_data = sql_exec(detect_sql, return_data=True)

			# 新数据插入数据库
			if not  detect_data[0][0]:
				insert_sql_tmp = "insert into bug_desc(host, vulnname, port, vulnseverity, vulnscore, vulnqod, vulndesc, vulndesctag, flags) value('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d)"
				insert_sql = insert_sql_tmp % (scan_ip, escape_string(vuln_name), escape_string(vuln_port), vuln_level, vuln_score, vuln_qod, escape_string(vuln_desc), escape_string(vuln_desc_tag), 0)
				sql_exec(insert_sql, return_data=False)

			i += 1
		return True
	else:
		return False

def del_task_data(gvm_obj=None, task_id=None, target_id=None, port_list_id=None, report_id=None):
	# 删除任务的临时数据
	gvm_obj.delete_task(task_id, ultimate=True)
	gvm_obj.delete_target(target_id, ultimate=True)
	gvm_obj.delete_port_list(port_list_id)
	gvm_obj.delete_report(report_id)

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

	# 程序核心逻辑
	try:
		gmp = login_gvm(GVM_USER, GVM_PWD)

		# 读取本地文件并分析结果, 结果存入mysql
		hRetTmp = open(task_tmp_file, 'w', encoding='utf-8')

		if os.path.exists(TASK_RET):
			with open(TASK_RET, 'r', encoding='utf-8') as hRet:
				for line in hRet:
					temp_line = json.loads(line)
					ret_opt_bool = get_scan_result(gvm_obj=gmp, task_id=temp_line['task_id'], report_id=temp_line['report_id'])


					if ret_opt_bool:
						# 已经扫描完成, 并分析了结果了的, 删除已经完成的任务的代码没有写
						del_task_data(gvm_obj=gmp, task_id=temp_line['task_id'], target_id=temp_line['target_id'], port_list_id=temp_line['portlist_id'], report_id=temp_line['report_id'])

						#gmp.delete_task(temp_line['task_id'])
						#gmp.delete_target(temp_line['target_id'])
						#gmp.delete_port_list(temp_line['portlist_id'])
						#gmp.delete_report(temp_line['report_id'])
						continue
					else:
						hRetTmp.write(json.dumps(temp_line) + '\n')
			hRetTmp.close()
			os.remove(TASK_RET)
			os.rename(task_tmp_file, TASK_RET)
		else:
			os.remove(task_tmp_file)
			logger.error('task result file not exist')

		# 测试代码
		#get_scan_result(gvm_obj=gmp, task_id='6833198d-a507-4f54-9322-9eeaa8a2a4dc', report_id='f54a9d9e-4e1f-4518-89b7-1df5e1b36b14')


	# 定时清理一下trashcan
		gmp.empty_trashcan()
	except Exception as e:
		logger.error(str(e), exc_info=True)


	'''程序运行结束，并显示运行了多久'''
	print ('')
	endtime = datetime.datetime.now()
	seconds = (endtime - starttime).seconds
	print ('程序执行完成，一共花费了 %d 秒' % (seconds))
	print ('-------------------------------------------------------------------------')