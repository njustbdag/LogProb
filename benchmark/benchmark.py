import sys

sys.path.append('../')
import os
import pandas as pd

input_dir = '../logs/'  # The input directory of log file
output_dir = 'LogProb_result/'  # The output directory of parsing results
from algorithm import logProb
from algorithm import evaluatorPAandFTA


benchmark_settings = {
    'HDFS': {
        'log_file': 'HDFS/HDFS_2k.log',
        'log_format': '<Date> <Time> <Pid> <Level> <Component>: <Content>',
        'regex': [r'blk_-?\d+', r'(\d+\.){3}\d+(:\d+)?'],
        'st': 0.84,
        'depth': 5,
        'delimiter': ' '
    },

    'Hadoop': {
        'log_file': 'Hadoop/Hadoop_2k.log',
        'log_format': '<Date> <Time> <Level> \[<Process>\] <Component>: <Content>',
        'regex': [r'(\d+\.){3}\d+'],
        'st': 0.9, #0.93,
        'depth': 3,
        'delimiter': ' '
    },

    'Spark': {
        'log_file': 'Spark/Spark_2k.log',
        'log_format': '<Date> <Time> <Level> <Component>: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\b[KGTM]?B\b', r'([\w-]+\.){2,}[\w-]+'],
        'st': 0.72,
        'depth': 3,
        'delimiter': ' '
    },

    'Zookeeper': {
        'log_file': 'Zookeeper/Zookeeper_2k.log',
        'log_format': '<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>',
        'regex': [r'(/|)(\d+\.){3}\d+(:\d+)?'],
        'st': 0.78,
        'depth': 4,
        'delimiter': ' '
    },

    'BGL': {
        'log_file': 'BGL/BGL_2k.log',
        'log_format': '<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>',
        'regex': [r'core\.\d+'],
        'st': 0.9, # 0.93,
        'depth': 6,
        'delimiter': ' |,'
    },

    'HPC': {
        'log_file': 'HPC/HPC_2k.log',
        'log_format': '<LogId> <Node> <Component> <State> <Time> <Flag> <Content>',
        'regex': [r'=\d+'],
        'st': 0.9,#0.91,
        'depth': 6,
        'delimiter': ' |='
    },

    'Thunderbird': {
        'log_file': 'Thunderbird/Thunderbird_2k.log',
        'log_format': '<Label> <Timestamp> <Date> <User> <Month> <Day> <Time> <Location> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+'],
        'st': 0.82,
        'depth': 3,
        'delimiter': ' '
    },

    'Windows': {
        'log_file': 'Windows/Windows_2k.log',
        'log_format': '<Date> <Time>, <Level>                  <Component>    <Content>',
        'regex': [r'0x.*?\s'],
        'st': 0.81,
        'depth': 3,
        'delimiter': ' |,|:'
    },

    'Linux': {
        'log_file': 'Linux/Linux_2k.log',
        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}'],
        'st': 0.7,
        'depth': 3,
        'delimiter': ' |='
    },

    'Andriod': {
        'log_file': 'Andriod/Andriod_2k.log',
        'log_format': '<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>',
        'regex': [r'(/[\w-]+)+', r'([\w-]+\.){2,}[\w-]+', r'\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b'],
        'st': 0.74,
        'depth': 6,
        'delimiter': ' |:|=|,'
    },

    'HealthApp': {
        'log_file': 'HealthApp/HealthApp_2k.log',
        'log_format': '<Time>\|<Component>\|<Pid>\|<Content>',
        'regex': [],
        'st': 0.87,
        'depth': 3,
        'delimiter': ' |=|,|:'
    },

    'Apache': {
        'log_file': 'Apache/Apache_2k.log',
        'log_format': '\[<Time>\] \[<Level>\] <Content>',
        'regex': [r'(\d+\.){3}\d+'],
        'st': 0.7,
        'depth': 3,
        'delimiter': ' '
    },

    'Proxifier': {
        'log_file': 'Proxifier/Proxifier_2k.log',
        'log_format': '\[<Time>\] <Program> - <Content>',
        'regex': [r'<\d+\ssec', r'([\w-]+\.)+[\w-]+(:\d+)?', r'\d{2}:\d{2}(:\d{2})*', r'[KGTM]B'],
        'st': 0.7,
        'depth': 3,
        'delimiter': ' |,'
    },

    'OpenSSH': {
        'log_file': 'OpenSSH/OpenSSH_2k.log',
        'log_format': '<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'([\w-]+\.){2,}[\w-]+'],
        'st': 0.76,
        'depth': 4,
        'delimiter': ' |='
    },

    'OpenStack': {
        'log_file': 'OpenStack/OpenStack_2k.log',
        'log_format': '<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>',
        'regex': [r'((\d+\.){3}\d+,?)+', r'/.+?\s', r'\d+'],
        'st': 0.795,  # 0.94
        'depth': 3,
        'delimiter': ' '
    },

    'Mac': {
        'log_file': 'Mac/Mac_2k.log',
        'log_format': '<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>',
        'regex': [r'([\w-]+\.){2,}[\w-]+'],
        'st': 0.78,  # 0.86
        'depth': 6,  # 3
        'delimiter': ' ',
    }

}

if __name__ == '__main__':

    benchmark_result = []
    df_compareParameters = None
    for dataset, setting in benchmark_settings.items():
        try:
            print('\n=== Evaluation on %s ===' % dataset)
            indir = os.path.join(input_dir, os.path.dirname(setting['log_file']))
            log_file = os.path.basename(setting['log_file'])
            parser = logProb.LogParser(setting['log_format'], indir, output_dir, rex=setting['regex'], st=setting['st'],
                                       depth=setting['depth'], delimiter=setting['delimiter'])
            time = parser.parse(log_file)
            PA, PTA, RTA, FTA = evaluatorPAandFTA.evaluate(
                groundtruth=os.path.join(os.path.join("../groundtruth", dataset), dataset + '_structured.csv'),
                parsedresult=os.path.join(output_dir, log_file + '_structured.csv'),
                template=os.path.join(os.path.join("../groundtruth", dataset), dataset + '_template.csv'),
                algorithm='LogProb', unique_enable=True)
            benchmark_result.append(
                [log_file, PA, PTA, RTA, FTA, setting['st'], setting['depth'], time])
        except Exception as e:
            print(e)

    print('\n=== Overall evaluation results ===')
    df_result = pd.DataFrame(benchmark_result,
                             columns=['Dataset','PA', 'PTA', 'RTA', 'FTA', 'st', 'depth', 'Time'])
    df_result.set_index('Dataset', inplace=True)
    print(df_result)
    df_result.to_csv('LogProb_benchmark_result.csv')

