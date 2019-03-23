# 从规则的文本中进一步获取足够多的信息;
import re
DBConfig = dict(host='127.0.0.1', port=27017, db_name='waf', username=None, password=None)

def get_data_by_rule_id(rule_id, DB="waf", collection_name="rule_txt"):
    from src.mongo import MongoConn
    DBConfig["db_name"] = DB
    # MongoConn(DBConfig).insert_data_uniq(get_all_ruletxt(), get_all_ruletxt(), key="rule_id")
    return list(MongoConn(DBConfig).db[collection_name].find({"rule_id": str(rule_id)}, projection={"_id": False}))[0]


## 例如返回状态码，严重性，规则ID，Tag, 完备性。所在文件，
def levelDeepData(rule_id):
    data = get_data_by_rule_id(rule_id)
    temp = data.copy()
    rule_txt = temp["rule_txt"]
    # 告警信息, 标签, 安全等级, 阶段， 版本， 完备性， 成熟性
    msg, tags, severity, phase, rev, maturity, accuracy, ver = "", [], "", "", "0", 0, 0, 'OWASP_CRS/0.0'
    for local_txt in rule_txt.split("\n"):
        tags_matched = re.match(".*?tag:'(.*?)',.*?", rule_txt)
        msg_matched = re.match(".*?msg:'(.*?)',.*?", local_txt)
        severity_matched = re.match(".*?severity:'(.*?)',.*?", local_txt)
        phase_matched = re.match(".*?phase:(.*?),.*?", local_txt)
        rev_matched = re.match(".*?rev:'(.*?)',.*?", local_txt)
        maturity_matched = re.match(".*?maturity:'(.*?)',.*?", local_txt)
        accuracy_matched = re.match(".*?accuracy:'(.*?)',.*?", local_txt)
        ver_matched = re.match(".*?ver:'(.*?)',.*?", local_txt)
        if msg_matched:
            msg = msg_matched.group(1)
        if severity_matched:
            severity = severity_matched.group(1)
        if phase_matched:
            phase = phase_matched.group(1)
        if rev_matched:
            rev = rev_matched.group(1)
        if maturity_matched:
            maturity = maturity_matched.group(1)
        if accuracy_matched:
            accuracy = accuracy_matched.group(1)
        if ver_matched:
            ver = ver_matched.group(1)
        if tags_matched:
            tags.append(tags_matched.group(1))
    params = dict(
        msg=msg,
        tags=tags,
        severity=severity,
        phase=phase,
        rev=rev,
        maturity=maturity,
        accuracy=accuracy,
        ver=ver,
    )
    # temp = dict({}, **params)
    temp = dict(temp, **params)
    return temp


def put_all_datas(DB="waf", collection_name="rule_txt"):
    from src.mongo import MongoConn
    DBConfig["db_name"] = DB
    # MongoConn(DBConfig).insert_data_uniq(get_all_ruletxt(), get_all_ruletxt(), key="rule_id")
    datas = list(MongoConn(DBConfig).db[collection_name].find(projection={"_id": False}))

    rule_majus = []
    for data in datas:
        temp = data.copy()
        rule_txt = temp["rule_txt"]
        # 告警信息, 标签, 安全等级, 阶段， 版本， 完备性， 成熟性
        msg, tags, severity, phase, rev, maturity, accuracy, ver = "", [], "", "", "0", 0, 0, 'OWASP_CRS/0.0'
        tags_matched = re.findall(".*?tag:'(.*?)',.*?", rule_txt)
        for local_txt in rule_txt.split("\n"):
            msg_matched = re.match(".*?msg:'(.*?)',.*?", local_txt)
            severity_matched = re.match(".*?severity:'(.*?)',.*?", local_txt)
            phase_matched = re.match(".*?phase:(.*?),.*?", local_txt)
            rev_matched = re.match(".*?rev:'(.*?)',.*?", local_txt)
            maturity_matched = re.match(".*?maturity:'(.*?)',.*?", local_txt)
            accuracy_matched = re.match(".*?accuracy:'(.*?)',.*?", local_txt)
            ver_matched = re.match(".*?ver:'(.*?)',.*?", local_txt)
            if msg_matched:
                msg = msg_matched.group(1).replace("%", "AcTaBle").replace("{", "ZHAXIX").replace("}", "XIXAHZ")
                matched2 = re.match("(.*?)AcTaBle.*", msg)
                if matched2:
                    msg = matched2.group(1)
            if severity_matched:
                severity = severity_matched.group(1)
            if phase_matched:
                phase = phase_matched.group(1)
            if rev_matched:
                rev = rev_matched.group(1)
            if maturity_matched:
                maturity = maturity_matched.group(1)
            if accuracy_matched:
                accuracy = accuracy_matched.group(1)
            if ver_matched:
                ver = ver_matched.group(1)

        if tags_matched:
            tags = list(tags_matched)
        params = dict(
            msg=msg,
            tags=tags,
            severity=severity,
            phase=phase,
            rev=rev,
            maturity=maturity,
            accuracy=accuracy,
            ver=ver,
        )
        # temp = dict({}, **params)
        temp = dict(temp, **params)
        rule_majus.append(temp)
    MongoConn(DBConfig).db[collection_name + "_maju"].remove()
    print(rule_majus)
    print("==================")
    MongoConn(DBConfig).db[collection_name + "_maju"].insert(rule_majus)


def show_data(DB="waf", collection_name="rule_txt"):
    from src.mongo import MongoConn
    DBConfig["db_name"] = DB
    # MongoConn(DBConfig).insert_data_uniq(get_all_ruletxt(), get_all_ruletxt(), key="rule_id")
    datas = list(MongoConn(DBConfig).db[collection_name + "_maju"].find(projection=["msg","rule_id","rev","phase"]))
    for data in datas:
        print(data)

if __name__ == '__main__':
    put_all_datas()
    show_data()






