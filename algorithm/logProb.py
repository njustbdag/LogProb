import math
import sys

import numpy as np
import regex as re
from datetime import datetime
import pandas as pd
import os
import hashlib
import calendar

months = list(calendar.month_abbr)
days = list(calendar.day_abbr)

'''
    logTemplate: 记录当前组节点中的模板字段
    logProb: 记录模板所对应的字段状态
    logIDL: 记录当前组节点中的日志消息索引
'''


class Logcluster:
    def __init__(self, logTemplate='', logProb=[], logIDL=None):
        self.logTemplate = logTemplate
        self.logProb = logProb
        if logIDL is None:
            logIDL = []
        self.logIDL = logIDL


class Node:
    def __init__(self, childD=None, depth=0, digitOrtoken=None):
        if childD is None:
            childD = dict()
        self.childD = childD
        self.depth = depth
        self.digitOrtoken = digitOrtoken


class LogParser:
    def __init__(self, log_format, indir='./', outdir='./result/', depth=4, st=0.4, rex=[], keep_para=True,
                 delimiter=None):
        self.path = indir
        self.depth = depth - 2
        self.st = st
        self.logName = None
        self.savePath = outdir
        self.df_log = None
        self.log_format = log_format
        self.rex = rex
        self.keep_para = keep_para
        self.delimiter = delimiter
        self.max_disSim = np.linalg.norm(np.array([0, 1, 0] - np.array([1, 0, 0])))
        self.static_vec = np.array([1, 0, 0])
        self.symbols_vec = np.array([0, 0, 1])

    def getProb(self, logmessageL, prob_dict):
        p_list = []
        for token in logmessageL:
            if token in prob_dict:
                p = prob_dict[token]
            else:
                vec_list = [0, 0, 0]
                for ch in token:
                    if ch.islower() or ch.isupper():
                        vec_list[0] += 1
                    elif ch.isdigit():
                        vec_list[1] += 1
                    else:
                        vec_list[2] += 1
                token_vec = np.array(vec_list)
                token_vec = token_vec / np.linalg.norm(token_vec)
                if np.linalg.norm(token_vec - self.symbols_vec) == 0:
                    p = 1
                else:
                    disSim = np.linalg.norm(self.static_vec - token_vec) / self.max_disSim
                    p = 1 - disSim
                prob_dict[token] = p
            p_list.append(p)
        return p_list

    # 使用向量相异度计算token和纯字母token的相异度disSim，并使用1-disSim表示该token可能为静态字段的概率
    def cmpProbability(self, str1, str2, p1, p2, event="", p_list=[], sim_list=[], str_flag=-1):
        len1 = len(p1)
        len2 = len(p2)
        sim = None
        for i in range(min(len1, len2)):
            if p1[i] == 1 and p2[i] < 1 and i < len2 - 1 and str_flag != 2:
                p_list.append(p2[i])
                sim_list.append(abs(p1[i] - p2[i]))
                event = ' '.join([event, '<*>'])
                event, p, sim = self.cmpProbability(str1[i:], str2[i + 1:], p1[i:], p2[i + 1:], event, p_list, sim_list,
                                                    str_flag=1)
                if sim is not None:
                    break
                else:
                    sim_list.pop()
                    p_list.pop()
            elif p2[i] == 1 and p1[i] < 1 and i < len1 - 1 and str_flag != 1:
                # print(p1[i])
                p_list.append(p1[i])
                sim_list.append(abs(p1[i] - p2[i]))
                event = ' '.join([event, '<*>'])
                event, p, sim = self.cmpProbability(str1[i + 1:], str2[i:], p1[i + 1:], p2[i:], event,p_list, sim_list,
                                                    str_flag=2)
                if sim is not None:
                    break
                else:
                    sim_list.pop()
                    p_list.pop()
            if str_flag != -1 and str1[i] != str2[i]:
                return event[:-4], p_list, None
            str_flag = -1
            p = math.sqrt(p1[i] * p2[i])
            if str1[i] != str2[i] and 1 >= p > self.st:
                sim_list.append(-1)
            else:
                sim_list.append(abs(p1[i] - p2[i]))

            if p == 1 or str1[i] == str2[i]:
                if p == 1 and str1[i] == str2[i]:
                    event = ' '.join([event, str1[i]])
                if p == 1 and str1[i] != str2[i]:
                    event = ' '.join([event, '<*>'])
                if p != 1 and str1[i] == str2[i]:
                    event = ' '.join([event, str1[i]])
            else:
                event = ' '.join([event, '<*>'])

            p_list.append(p)

        if len1 != len2 and sim is None:
            if len1 > len2:
                p_rest = p1[len2:]
            else:
                p_rest = p2[len1:]
            if p_rest.count(1.0) > 1:
                sim = -1
            event = ' '.join([event, '<*>'])

        if sim is None:
            tmp_list = sim_list.copy()
            if len(tmp_list) == 0:
                return None, None, 0
            for i, item in enumerate(tmp_list):
                if item != -1:
                    tmp_list[i] = math.exp(-item)
            sim = sum(tmp_list) / len(tmp_list)
            event = event.strip().split()
        # 由于循环是针对较短的日志，较长的剩余部分需要额外的处理
        return event, p_list, sim

    def treeSearch(self, rn, seq, probs, logID):  # 第二种搜索树结构对应的遍历过程
        parentn = rn
        retLogClust = None
        currentDepth = 0
        logClustL = []
        for i, token in enumerate(seq):
            if currentDepth >= self.depth:
                break
            if probs[i] != 1:
                continue
            else:
                if len(parentn.childD) == 0: return None
                if token in parentn.childD.keys():
                    parentn = parentn.childD[token]
                    currentDepth += 1
                else:
                    return None

        # 将当前值节点的所有组节点都加入到候选模板集合中
        for key, childD in parentn.childD.items():
            if 'templates' == key:
                logClustL += childD

        if len(logClustL) == 0: return None
        retLogClust = self.fastMatch(logClustL, seq, probs)
        if retLogClust is not None:
            retLogClust.logIDL.append(logID)
        return retLogClust

    def fastMatch(self, logClustL, seq, prob):
        retLogClust = None
        maxSim = -1
        maxClust = None
        maxTemplate = None
        maxProb = None
        for logClust in logClustL:
            newTemplate, newProb, curSim = self.cmpProbability(logClust.logTemplate, seq, logClust.logProb, prob, "",
                                                               [], [])
            if newTemplate is None: continue
            if curSim > maxSim:
                maxSim = curSim
                maxClust = logClust
                maxTemplate = newTemplate
                maxProb = newProb

        if maxSim >= self.st:
            maxClust.logTemplate = maxTemplate
            maxClust.logProb = maxProb
            retLogClust = maxClust

        return retLogClust

    def addSeqToSearchTree(self, rn, logClust):  # 第二种搜索树结构,仅保存模板中prob为1的静态字段作为树的值节点
        parentn = rn
        currentDepth = 0
        for i, currentToken in enumerate(logClust.logTemplate):
            if currentDepth >= self.depth:
                break
            if logClust.logProb[i] == 1:
                if currentToken not in parentn.childD.keys():
                    parentn.childD[currentToken] = Node(depth=currentDepth + 1, digitOrtoken=currentToken)
                parentn = parentn.childD[currentToken]
                currentDepth += 1
        if 'templates' not in parentn.childD.keys():
            parentn.childD['templates'] = []
        parentn = parentn.childD['templates']
        parentn.append(logClust)

    def outputResult(self, logClustL):
        log_templates = [0] * self.df_log.shape[0]
        log_templateids = [0] * self.df_log.shape[0]
        df_events = []
        for logClust in logClustL:
            template_str = ' '.join(logClust.logTemplate)
            occurrence = len(logClust.logIDL)
            template_id = hashlib.md5(template_str.encode('utf-8')).hexdigest()[0:8]
            for logID in logClust.logIDL:
                logID -= 1
                log_templates[logID] = template_str
                log_templateids[logID] = template_id
            df_events.append([template_id, template_str, occurrence])
        self.df_log['EventId'] = log_templateids
        self.df_log['EventTemplate'] = log_templates

        if self.keep_para:
            self.df_log["ParameterList"] = self.df_log.apply(self.get_parameter_list, axis=1)
        self.df_log.to_csv(os.path.join(self.savePath, self.logName + '_structured.csv'), index=False)

        occ_dict = dict(self.df_log['EventTemplate'].value_counts())
        df_event = pd.DataFrame()
        df_event['EventTemplate'] = self.df_log['EventTemplate'].unique()
        df_event['EventId'] = df_event['EventTemplate'].map(lambda x: hashlib.md5(x.encode('utf-8')).hexdigest()[0:8])
        df_event['Occurrences'] = df_event['EventTemplate'].map(occ_dict)
        df_event.to_csv(os.path.join(self.savePath, self.logName + '_templates.csv'), index=False,
                        columns=["EventId", "EventTemplate", "Occurrences"])

    def parse(self, logName):
        print('Parsing file: ' + os.path.join(self.path, logName))
        start_time = datetime.now()
        self.logName = logName
        self.load_data()
        rootNode = Node()
        logCluL = []
        prob_dict = {}
        count = 1
        try:
            idx = 0
            for lineId, content in zip(self.df_log['LineId'], self.df_log['Content']):
                logID = lineId
                logmessageL = self.preprocess(content)
                logmessageP = self.getProb(logmessageL, prob_dict)
                matchCluster = self.treeSearch(rootNode, logmessageL, logmessageP, logID)

                # Match no existing log cluster
                if matchCluster is None:
                    newCluster = Logcluster(logTemplate=logmessageL, logProb=logmessageP, logIDL=[logID])
                    logCluL.append(newCluster)
                    self.addSeqToSearchTree(rootNode, newCluster)

                count += 1
                idx += 1
                # if count % 1000 == 0 or count == len(self.df_log):
                #     print('Processed {0:.1f}% of log lines.'.format(count * 100.0 / len(self.df_log)))

            if not os.path.exists(self.savePath):
                os.makedirs(self.savePath)
            self.outputResult(logCluL)
        except Exception as e:
            print(count)
            print(e)

        parsing_time = datetime.now() - start_time

        print('Parsing done. [Time taken: {!s}]'.format(parsing_time))
        return parsing_time.total_seconds()

    def load_data(self):
        headers, regex = self.generate_logformat_regex(self.log_format)
        self.df_log = self.log_to_dataframe(os.path.join(self.path, self.logName), regex, headers, self.log_format)

    def preprocess(self, line):
        if self.delimiter != ' ':
            for delimiter in self.delimiter.split('|'):
                line = line.replace(delimiter, ' ' + delimiter + ' ')
            tokens = list(filter(lambda x: x != '', re.split(' ', line)))
        else:
            tokens = list(filter(lambda x: x != '', line.strip().split()))
        for idx, token in enumerate(tokens):
            if token in months:
                tokens[idx] = str(months.index(token))
            if token in days:
                tokens[idx] = str(days.index(token) + 1)
        return tokens

    def log_to_dataframe(self, log_file, regex, headers, logformat):
        """ Function to transform log file to dataframe
        """
        log_messages = []
        linecount = 0
        with open(log_file, 'r') as fin:
            for line in fin.readlines():
                try:
                    match = regex.search(line.strip())
                    message = [match.group(header) for header in headers]
                    log_messages.append(message)
                    linecount += 1
                except Exception as e:
                    pass
        logdf = pd.DataFrame(log_messages, columns=headers)
        logdf.insert(0, 'LineId', None)
        logdf['LineId'] = [i + 1 for i in range(linecount)]
        return logdf

    def generate_logformat_regex(self, logformat):
        """ Function to generate regular expression to split log messages
        """
        headers = []
        # 使用括号捕获分组，默认保留分割符
        splitters = re.split(r'(<[^<>]+>)', logformat)
        regex = ''
        for k in range(len(splitters)):
            if k % 2 == 0:
                splitter = re.sub(' +', '\\\s+', splitters[k])
                regex += splitter
            else:
                header = splitters[k].strip('<').strip('>')
                regex += '(?P<%s>.*?)' % header
                headers.append(header)
        regex = re.compile('^' + regex + '$')
        return headers, regex

    def get_parameter_list(self, row):
        template_regex = re.sub(r"<.{1,5}>", "<*>", row["EventTemplate"])
        if "<*>" not in template_regex: return []
        template_regex = re.sub(r'([^A-Za-z0-9])', r'\\\1', template_regex)
        template_regex = re.sub(r'\\ +', r'\s+', template_regex)
        template_regex = "^" + template_regex.replace("\<\*\>", "(.*?)") + "$"
        parameter_list = re.findall(template_regex, row["Content"])
        parameter_list = parameter_list[0] if parameter_list else ()
        parameter_list = list(parameter_list) if isinstance(parameter_list, tuple) else [parameter_list]
        return parameter_list
