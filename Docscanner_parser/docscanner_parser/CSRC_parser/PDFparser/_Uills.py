import numpy as np
import pandas as pd
import os

def tree_model_to_dict(model, index):
    return eval(
        model.get_booster()[index].get_dump(dump_format="json")[0].replace("\n", "").replace("\t", "").replace(" ","").replace("'", ""))


def dict_to_rule(_dict):
    return_dict = {}

    def recursive_dict(values):
        if type(values) == type({}):
            temp = {}
            value = values
            if "leaf" in value:
                temp['leaf'] = value['leaf']
            else:
                temp['split'] = value['split']
                temp['yes'] = value['yes']
                temp['no'] = value['no']
                temp['split_condition'] = value['split_condition']
                temp['missing'] = value['missing']

            return_dict[value['nodeid']] = temp
            try:
                children = value['children']
                recursive_dict(children)
            except KeyError:
                pass
        elif type(values) == type([]):
            for value in values:
                temp = {}
                if "leaf" in value:
                    temp['leaf'] = value['leaf']
                else:
                    temp['split'] = value['split']
                    temp['yes'] = value['yes']
                    temp['no'] = value['no']
                    temp['split_condition'] = value['split_condition']
                    temp['missing'] = value['missing']
                return_dict[value['nodeid']] = temp
                try:
                    children = value['children']
                    recursive_dict(children)
                except KeyError:
                    pass

    recursive_dict(_dict)
    return return_dict


def get_leaf(_rule, x, model_index):
    def get_leaf_index(_rule, x):
        i = 0
        while 1:
            cur_rule = _rule.get(i)
            if "leaf" in cur_rule:
                break
            split = cur_rule['split']
            split_condition = cur_rule['split_condition']
            if x[split] < split_condition:
                i = cur_rule['yes']
            elif x[split] >= split_condition:
                i = cur_rule['no']
            else:
                i = cur_rule['missing']
        return i

    def series_leaf_value(_rule, x):
        index = get_leaf_index(_rule, x)
        return _rule.get(index)['leaf']

    if isinstance(x, pd.Series):
        return series_leaf_value(_rule, x)
    elif isinstance(x, pd.DataFrame):
        x['tree_{}'.format(model_index)] = x.apply(lambda x: series_leaf_value(_rule, x), axis=1)


def get_logistic_value(value):
    # return 1 / (1 + np.exp(-1 * value))
    # return np.exp(-1 * value) / (1 + np.exp(-1 * value))
    return np.exp(-1 * value) / (1 + np.exp(-1 * value))



def get_outlier(_df, **kwargs):
    #_df, kwargs = _class1.loc[:, column_name].copy(), {"columns":[columns[0], columns[1]]}
    try:
        _column_name = kwargs['columns']
    except NameError:
        _column_name = ['q1', 'q3']
        kwargs = {}

    isq3 = True
    isq1 = True
    try:
        isq3 = kwargs['q3']
    except KeyError:
        pass
    try:
        isq1 = kwargs['q1']
    except KeyError:
        pass

    if len(_column_name) == 1:
        column_name = _column_name[0]
    elif type(_column_name) == type(""):
        column_name = _column_name
    else:
        column_name = []
        for column in _column_name:
            column_name.append(column)

    q1 = _df.quantile(0.25)
    q3 = _df.quantile(0.75)
    iqr = q3 - q1
    i = 0
    while (iqr == 0).sum() > 0:
        _df = _df.drop(_df.loc[_df.idxmax().to_numpy()].index, inplace=False)
        q1 = _df.quantile(0.25)
        q3 = _df.quantile(0.75)
        iqr = q3 - q1
        if i > 3:
            break
        i+=1
    condition = None
    # if type(column_name) == type(""):
    if isq1 and isq3:
        condition = (_df[column_name] > (q3[column_name] + 1.5 * iqr[column_name])) \
                    | (_df[column_name] < (q1[column_name] - 1.5 * iqr[column_name]))
    elif isq1:
        condition = (_df[column_name] < (q1[column_name] - 1.5 * iqr[column_name]))
    elif isq3:
        condition = (_df[column_name] > (q3[column_name] + 1.5 * iqr[column_name]))

    return_df = None
    try:
        return_df = _df.drop(condition[condition.sum(axis=1) == 1].index, inplace=False)
    except ValueError:
        return_df = _df.drop(condition[condition==True].index, inplace=False)

    return _df



def create_directory(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print("Error: Creating directory. " + directory)
        exit()