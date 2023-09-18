import re
import pandas as pd
import os


def getgroundTruthParams(structured_path, template_path, dataset):
    # 将标准模板的csv文件读入，增加一列参数列
    # 同时在识别参数的过程中记录包含参数值唯一的模板，其集合记作TU，而参数值都不唯一的模板，其集合记作TD
    df_structured = pd.read_csv(structured_path)
    df_template = pd.read_csv(template_path)
    log_params = [0] * df_structured.shape[0]
    template_flag = [0] * df_template.shape[0]
    eventIds = df_structured['EventId'].unique()
    for eventId in eventIds:
        try:
            template = df_structured[df_structured['EventId'] == eventId]['EventTemplate'].unique()[0]
            # 处理模板中重复的通配符
            template = template.split(' ')
            for idx, token in enumerate(template):
                if '<*>' in token:
                    template[idx] = '<*>'
            template = ' '.join(template)
            params = {}
            items = df_structured[df_structured['EventId'] == eventId]
            for index, item in items.iterrows():
                content = item['Content']
                item_param = identifyParams(content, template, params)
                log_params[item['LineId'] - 1] = item_param
            # 判断模板是否对应单一的日志或包含单一的参数值
            flag, template = replaceUniqueParam(params, template)
            index = df_template[df_template['EventId'] == eventId].index.tolist()[0]
            template_flag[index] = flag
            df_template.iloc[index, 1] = template
        except Exception as e:
            print(eventId)
            return dataset
    df_structured['Parameters'] = log_params
    df_template['TemplateFlag'] = template_flag
    df_structured.to_csv(os.path.join("../groundtruth", dataset + "_structured.csv"), index=False)
    df_template.to_csv(os.path.join("../groundtruth", dataset + "_template.csv"), index=False)


# 检查模板包含的每个参数所对应的值是否唯一
def identifyParams(content, template, params):
    template = list(filter(lambda x: x != '', template.split("<*>")))
    content = content.strip()  # 去除头尾的空格
    count = 0
    start_index = 0
    item_param = []
    for segment in template:
        result = content.find(segment)
        param = content[: result]
        start_index = result + len(segment)
        content = content[start_index:]  # 移除已识别部分，更新模板内容
        if len(param) == 0: continue
        # print(param)
        if count in params.keys():
            params[count].append(param)
        else:
            params[count] = [param]
        item_param.append(param)
        count += 1
    param = content[:]
    if len(param) > 0:
        if count in params.keys():
            params[count].append(param)
        else:
            params[count] = [param]
        item_param.append(param)
    return item_param


def replaceUniqueParam(params, template):
    # 将模板中数值唯一的参数替换为对应值
    num_wildcards = template.count('<*>')
    flag = False
    count = 0
    substr = '\\<\\*\\>'
    addr = [addr_.start() for addr_ in re.finditer(substr, template)]
    offset = 0  # 记录替换之后addr的偏移量
    for key, item in params.items():
        paramSet = set(item)
        if len(paramSet) == 1:
            flag = True
            param = list(paramSet)[0]
            template = template[:addr[count] + offset] + param + template[addr[count] + 3 + offset:]
            offset += len(param) - 3
        count += 1
    return flag, template


def file_name_walk(file_dir):
    for root, dirs, files in os.walk(file_dir):
        return dirs
        # print("root", root)  # 当前目录路径
        # print("dirs", dirs)  # 当前路径下所有子目录
        # print("files", files)  # 当前路径下所有非目录子文件


def mergeWildcards(template_list):
    # 合并连续出现的多个通配符
    flag = False
    for idx, item in enumerate(template_list):
        if '<*>' in item:
            if flag:
                template_list[idx] = ''
            else:
                flag = True
                template_list[idx] = '<*>'
        else:
            flag = False
    template_list = list(filter(lambda x: x != '', template_list))
    return template_list


def replaceWildcards(template):
    # HDFS
    wildcards = ['/<*>/part-<*>. blk_<*>', '/<*>/blk_<*>', '/<*>:<*>', '<*>:<*>:', '<*>:<*>', 'blk_<*>', '/<*>:',
                 '/<*>', '<*>:']
    # BGL
    b_wildcards = ['core.<*>', 'chdir(<*>)', 'U<*>', 'J<*>', '(<*>)', 'instruction......<*>', 'bglio<*>',
                   'ip=<*>', 'v=<*>', 't=<*>', 'status=M']
    wildcards = wildcards + b_wildcards
    template = re.sub('\d+', '<*>', template)
    for wildcard in wildcards:
        template = template.replace(wildcard, ' <*> ')
    return template


def processDelimiter(template, algorithm):
    if algorithm == 'Brain':  # 处理Brain中将”<*>: Got“分割为”<*> Got“带来的问题
        if '<*> Got' in template:
            template = template.replace('<*> Got', '<*>:Got')
        if '<*> Failed' in template:
            template = template.replace('<*> Failed', '<*>:Failed')
        if '<*> Exception' in template:
            template = template.replace('<*> Exception', '<*>:Exception')
        if 'ruser= ' not in template:
            template = re.sub('\=\s*\<\*\>', '=<*>', template)  # 处理"= <*>"
    if algorithm == 'MoLFI':  # 处理MoLFI中的符号表示带来的问题
        template = re.sub('\s\*\s', '<*>', template)
        template = re.sub('\[\s', '[', template)
        template = re.sub('\s\]', ']', template)
        template = re.sub('\(\s', '(', template)
        template = re.sub('\s\)', ')', template)
        template = re.sub('[^a-zA-Z0-9(\<\*\>)]', '', template)
    if algorithm == 'Lenma':
        template = re.sub('\s\*\s', ' <*> ', template)
        template = re.sub('\s*\*\s', ' <*> ', template)
        template = re.sub('\s\*\s*', ' <*> ', template)
    if algorithm == 'LogCluster':
        template = re.sub('\*\{\d+\,\d+\}', '<*>', template)
    if 'HRESULT' in template:
        template = re.sub('\[\s*', '[', template)
    template = re.sub('\"\<\*\>\"', '<*>', template)  # 处理Android日志中出现的通配符"<*>"
    template = re.sub('time\(\ss\)\s', 'time(s)', template)  # 修复Brain解析结果中由于分隔符导致的静态字段出现空格的问题
    template = re.sub('\_\s\<\*\>', '<*>', template)  # 处理Hadoop中的"_ <*>"
    template = re.sub('\_\s', '_', template)
    template = re.sub('(\<\*\>\:)+', '<*>', template)  # 处理Mac日志中的[<*>:<*>:<*>.<*>]
    template = re.sub('\<\<\<\*\>\>', '<*>', template)  # 处理Mac日志中的<<*>>
    template = re.sub('\.\.\s', '..', template)  # 处理BGL日志中的".. "
    template = re.sub('\<\*\>\s?\-', '<*>', template)  # 处理Windows日志中"<*> -"
    template = re.sub('\s?\,\s?', ' ', template)  # 解决Android日志中","分隔符导致程序无法正确识别参数位置的问题
    template = re.sub('\:\<\*\>', ': <*>', template)  # 解决HealthApp日志中":"分隔符导致程序无法正确识别参数位置的问题
    if algorithm == 'LogProb':
        template = re.sub('\s*\=\s*\<\*\>', ' = <*>', template)  # 解决Android日志中"="分隔符导致程序无法正确识别参数位置的问题
        template = re.sub('\s*\,\s*', ' , ', template)  # 处理分隔符产生的空格导致的匹配错误
        template = re.sub('\s*\=\s*', ' = ', template)
        template = re.sub('\s*\:\s*', ' : ', template)
    return template


def cmpTemplate(groudtruth_template, parsed_template, algorithm, fileName):
    flag = True
    if 'ambient = <*>' in groudtruth_template:
        print('debug')
    parsed_template = processDelimiter(parsed_template, algorithm)
    groudtruth_template = processDelimiter(groudtruth_template, algorithm)
    parsed_list = mergeWildcards(parsed_template.split())
    gt_list = mergeWildcards(groudtruth_template.split())

    if len(parsed_list) != len(gt_list):
        flag = False
    else:
        # 模板这边还需要再次处理"<*>"的匹配
        for idx, item in enumerate(gt_list):
            if gt_list[idx] == parsed_list[idx]:
                continue
            elif '<*>' in gt_list[idx] and '<*>' in parsed_list[idx]:
                continue
            else:
                flag = False
                break
    return flag


def getAccuracy(series_groundtruth, series_parsedlog, df_groundtruth, df_parsedlog, fileName, template, algorithm, unique_enable):
    cmpTP = []
    df_template = pd.read_csv(template)
    series_parsedlog_valuecounts = series_parsedlog.value_counts()
    accurate_events = 0  # determine how many lines are correctly parsed
    accurate_templates = 0  # 记录文本解析准确的模板数量
    try:
        for parsed_eventId in series_parsedlog_valuecounts.index:
            logIds = series_parsedlog[series_parsedlog == parsed_eventId].index
            series_groundtruth_logId_valuecounts = series_groundtruth[logIds].value_counts()
            cluster_flag = False
            parsed_template = df_parsedlog[df_parsedlog['EventId'] == parsed_eventId]['EventTemplate'].unique()[0]
            if algorithm == 'MoLFI':
                parsed_template = parsed_template.replace('#spec#', '<*>')
            if series_groundtruth_logId_valuecounts.size == 1:
                groundtruth_eventId = series_groundtruth_logId_valuecounts.index[0]
                if logIds.size == series_groundtruth[series_groundtruth == groundtruth_eventId].size:
                    cluster_flag = True
                    # 判断模板是否属于包含唯一值的模板
                    flag_TU = False
                    if unique_enable:
                        if df_template[df_template['EventId'] == groundtruth_eventId]['TemplateFlag'].unique()[0]:
                            # 如果模板属于TU模板，那么通过两种方式比较，满足任意一种都视作解析正确
                            flag_TU = True
                    groudtruth_template = \
                        df_groundtruth[df_groundtruth['EventId'] == groundtruth_eventId]['EventTemplate'].unique()[0]
                    flag = cmpTemplate(groudtruth_template, parsed_template, algorithm, fileName)
                    #  评估模板与标准模板的文本是否一致
                    if flag:
                        accurate_events += logIds.size
                        accurate_templates += 1
                    elif flag_TU and unique_enable:
                        groudtruth_template = \
                            df_template[df_template['EventId'] == groundtruth_eventId]['EventTemplate'].unique()[0]
                        flag = cmpTemplate(groudtruth_template, parsed_template, algorithm, fileName)
                        if flag:
                            accurate_events += logIds.size
                            accurate_templates += 1
                    else:
                        # print('not match')
                        pass
                    if flag:
                        cmpTP.append([groundtruth_eventId, parsed_template, groudtruth_template, flag, '', logIds.size])
                    else:
                        cmpTP.append([groundtruth_eventId, parsed_template, groudtruth_template, flag, 'content error',
                                      logIds.size])
            #  不匹配的模板
            if not cluster_flag:
                cmpTP.append(['', parsed_template, '', cluster_flag, 'clustering error', logIds.size])

        df_cmpTP = pd.DataFrame(cmpTP,
                                columns=['EventId', 'ParsedTemplate', 'GtTemplate', 'Match', 'Error', 'Occurrence'])
        savePath = os.path.join("../benchmark", algorithm + '_evaluate_result')
        if not os.path.exists(savePath):
            os.makedirs(savePath)
        df_cmpTP.to_csv(os.path.join(savePath, fileName + '.csv'), index=False)
    except Exception as e:
        print(parsed_eventId)
        print(e)
    accuracy = float(accurate_events) / series_groundtruth.size
    PTA = accurate_templates / len(series_parsedlog_valuecounts)
    RTA = accurate_templates / len(series_groundtruth.value_counts())
    if (PTA+RTA) == 0:
        FTA = 0
    else:
        FTA = 2 * PTA * RTA / (PTA + RTA)
    return accuracy, PTA, RTA, FTA


def evaluate(groundtruth, parsedresult, template, algorithm, unique_enable):
    df_groundtruth = pd.read_csv(groundtruth)
    fileName = os.path.basename(os.path.dirname(groundtruth))
    df_parsedlog = pd.read_csv(parsedresult)
    # Remove invalid groundtruth event Ids
    null_logids = df_groundtruth[~df_groundtruth['EventId'].isnull()].index
    df_groundtruth = df_groundtruth.loc[null_logids]
    df_parsedlog = df_parsedlog.loc[null_logids]
    accuracy, PTA, RTA, FTA = getAccuracy(df_groundtruth['EventId'], df_parsedlog['EventId'], df_groundtruth,
                                          df_parsedlog, fileName, template, algorithm, unique_enable)
    print('PA: %.4f, PTA: %.4f, RTA: %.4f, FTA: %.4f' % (
        accuracy, PTA, RTA, FTA))
    return accuracy, PTA, RTA, FTA


def formatDataFrame(df, columns):
    for column in columns:
        df[column] = df[column].apply(lambda x: format(x, '.4f'))

