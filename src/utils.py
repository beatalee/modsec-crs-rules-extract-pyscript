# coding:utf-8

import re
import os

LocalBasePath = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RuleDir = os.path.join(LocalBasePath, *["rules", ])


def get_rule_txt_depend_context(line_index, lines, offset=150,):
    maxIndex = len(lines) - 1
    RileTxtStartLine, RileTxtEndLine = 0, 0
    upIndexList = [line_index - i for i in range(offset)]
    for index in upIndexList:
        if re.match("SecRule .*?", lines[index]):
            RileTxtStartLine = index
            if(RileTxtStartLine == line_index):
                return lines[line_index: line_index+1]
            break

    downIndexList = [line_index + i for i in range(offset)]
    for index in downIndexList:
        if index > maxIndex or lines[index] == "\n":
            RileTxtEndLine = index-1
            break
    return lines[RileTxtStartLine:RileTxtEndLine]


def get_ruleparams_by_filename(filename):
    rule_infos = []
    with open(os.path.join(RuleDir, filename), "r+", encoding="utf-8") as f:
        lines = f.readlines()
        f.close()
    for line_index in range(len(lines)):
        if re.match("#.*?", lines[line_index]):
            continue
        matched = re.match("\s.*?id:(\d+),.*?", lines[line_index])
        if matched:
            temp=dict(
                rule_txt = "".join(get_rule_txt_depend_context(line_index, lines)),
                rule_id = matched.group(1),
                rule_belong_file = filename,
            )
            rule_infos.append(temp)
    return rule_infos

def get_all_ruletxt():
    results = []
    filenames = [filename for filename in os.listdir(RuleDir) \
                 if re.match(".*?conf", filename)]
    for filename in filenames:
        results.extend(get_ruleparams_by_filename(filename))
    return results

def save_data(DB="waf", collection_name="rule_txt"):
    from src.mongo import MongoConn
    DBConfig = dict(host='127.0.0.1', port=27017, db_name='waf', username=None, password=None)
    DBConfig["db_name"] = DB
    # MongoConn(DBConfig).insert_data_uniq(get_all_ruletxt(), get_all_ruletxt(), key="rule_id")
    MongoConn(DBConfig).db[collection_name].insert(get_all_ruletxt())





