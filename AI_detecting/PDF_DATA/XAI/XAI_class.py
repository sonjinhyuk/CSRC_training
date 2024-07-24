import seaborn as sns
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import numpy as np
from tqdm import tqdm
import shap
from shap._explanation import Explanation
import time
from shap_plot.modify_shatplot import waterfall, summary_plot
import os
lime_num_features = 10
import pandas as pd
import pickle
import joblib
from sklearn.preprocessing import MinMaxScaler

def create_directory(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print("Error: Creating directory. " + directory)
        exit()


chart_class = ['normal', 'malware']

class XAI_class:
    def __init__(self,
                 base_dir: str= "../",
                 result_dir: str = "AI_detecting/PDF_DATA/XAI/xai_result",
                 train_file_name="isec_train_scaled.csv"):

        self.base_dir = base_dir
        self.result_dir = result_dir
        self.scaler = joblib.load(open('../scaler.save', 'rb'))

        self.df = pd.read_csv("{}{}".format(base_dir, train_file_name), index_col=0)
        self.model = None
        with open(f'{base_dir}/AI/models/max_acc.pickle', 'rb') as f:
            self.model = pickle.load(f)
        self.shap_train_df, self.data_train_df, self.base_line_train_df, self.shap_exp_train = self.__shap_tabular__()

    def set_Xy(self, df):
        return df.iloc[:, :-1], df.loc[:, 'class']

    # LIME용 예측 계수의 준비
    def predict_fn(self, X):
        if len(X.shape) == 1:
            return self.model.predict_proba(X.reshape(1, -1))[0]
        else:
            return self.model.predict_proba(X)

    def __shap_tabular__(self, df=None, target_name="Train"):
        if df is None:
            df = self.df
        X, y = self.set_Xy(df)
        shap_exp = shap.TreeExplainer(self.model)
        try:
            shap_df = pd.read_csv("xai_result/shap_result/shap.result.csv",index_col=0)
            data_df = pd.read_csv("xai_result/shap_result/shap.data.csv", index_col=0)
            base_line_df = pd.read_csv("xai_result/shap_result/shap.baseline.csv", index_col=0)
            return shap_df, data_df, base_line_df, shap_exp
        except FileNotFoundError:
            pass


        expected_value = shap_exp.expected_value
        # shap.force_plot(shap_exp.expected_value(self.))
        # for i in range(X.shape[-1])
        shap_data = {}
        columns = None

        for i in tqdm(range(X.shape[0]), desc=target_name):
            shap_x = X.iloc[i:i + 1, :]
            if columns is None:
                columns = list(shap_x.columns)
            temp_shap = {}
            _class = int(y.iloc[i])
            prediction_probabilies = self.model.predict_proba(shap_x)
            prediction = prediction_probabilies[0].argmax()
            predict_result = "Wrong({})".format(chart_class[_class])
            if prediction == _class:
                predict_result = "Correct({})".format(chart_class[_class])
            fname = shap_x.iloc[0].name.split("/")[-1]
            temp_shap["class"] = _class
            temp_shap["predict"] = predict_result
            shap_data[fname] = temp_shap

            # shap.force_plot(expected_value, shap_value, shap_x, matplotlib=True, show=False)
            # plt.clf()
            # shap.decision_plot(expected_value, shap_value, shap_x)
            # plt.
        create_directory("{}/XAI/xai_result/".format(self.base_dir))
        create_directory("{}/XAI/xai_result/shap_result/".format(self.base_dir))
        # shap_values = shap_exp.shap_values(self.df_train_data.iloc[:, 1:-4])
        shap_values = shap_exp(X)
        shap.summary_plot(shap_values, X, show=False)
        plt.savefig("xai_result/shap_result/shap.summary_plot.png".format(self.base_dir))
        plt.clf()

        shap_interaction_values = shap_exp.shap_interaction_values(X)
        shap.summary_plot(shap_interaction_values, X, show=False)
        plt.savefig("xai_result/shap_result/shap.interaction.summary_plot.png".format(self.base_dir))
        plt.clf()

        shap_value = shap_values.values
        origin_data = shap_values.data
        base_line = shap_values.base_values

        df = pd.DataFrame(shap_data).T
        shap_df = pd.concat([df, pd.DataFrame(shap_value, index=df.index, columns=columns)], axis=1)
        data_df = pd.concat([df, pd.DataFrame(origin_data, index=df.index, columns=columns)], axis=1)
        base_line_df = pd.concat([df, pd.DataFrame(base_line, index=df.index, columns=['base_line'])], axis=1)
        shap_df.to_csv("xai_result/shap_result/shap.result.csv")
        data_df.to_csv("xai_result/shap_result/shap.data.csv")
        base_line_df.to_csv("xai_result/shap_result/shap.baseline.csv")

        return shap_df, data_df, base_line_df, shap_exp


    def target_shap_value(self, test_df):
        # if similar_df is None:
        #     print("please input train similar data")
        #     return
        baseline_X = self.df.iloc[:, :-1]
        shap_x = test_df.iloc[:, :-1]
        fname = shap_x.index[0].split("/")[-1]
        _class = test_df.iloc[:, -1].values[0]
        shap_values = self.shap_train_df
        feature_name = self.data_train_df.iloc[:, 2:].columns
        shap_values = Explanation(shap_values.iloc[:, 2:].values,
                                  base_values=self.base_line_train_df.iloc[:, 2:].values.reshape(-1),
                                  data=self.data_train_df.iloc[:, 2:].values,
                                  feature_names=feature_name)
        train_df = self.df
        train_df = train_df.reset_index()
        normal_index = list(train_df[train_df['class'] == 0].index)
        malware_index = list(train_df[train_df['class'] == 1].index)

        # shap_normal_mean = shap_values[normal_index].mean()
        normal_shap_data = baseline_X.iloc[normal_index].values.mean(axis=0)
        normal_shap_data = pd.DataFrame(normal_shap_data, columns=['normal']).T
        normal_shap_data.columns = feature_name
        malware_shap_data = baseline_X.iloc[malware_index].values.mean(axis=0)
        malware_shap_data = pd.DataFrame(malware_shap_data, columns=['malware']).T
        malware_shap_data.columns = feature_name
        exp = self.shap_exp_train
        target_shap_value = exp(shap_x)
        normal_shap_value = exp(normal_shap_data)
        malware_shap_value = exp(malware_shap_data)
        prediction_probabilies = self.model.predict_proba(shap_x)
        prediction = prediction_probabilies.argmax()
        predict_result = "Wrong({})".format(chart_class[_class])
        if prediction == _class:
            predict_result = "Correct({})".format(chart_class[_class])
        save_name = "{}_{}".format(predict_result, fname)

        # shap.plots.waterfall(shap_values[0], show=False)
        _, waterfall_df = waterfall([target_shap_value[0], normal_shap_value[0], malware_shap_value[0]], show=False)

        plt.savefig("xai_result/shap_result/{}_waterfall.png".format(save_name))
        plt.clf()

        output_name = "xai_result/shap_result/{}_shap.summary_plot".format(fname)
        summary_plot(shap_values, target_data=[target_shap_value, normal_shap_value, malware_shap_value], show=False, plot_type="dot", output_name=output_name, cmap="binary")
        plt.savefig("{}.png".format(output_name))
        plt.clf()

def read_data(filename):
    try:
        _class = int(filename.split("_")[-1].split(".")[0])
    except AttributeError:
        _class = int(str(filename).split("_")[-1].split(".")[0])
    temp_df = pd.read_csv(f"{filename}", index_col=0).T
    temp_df = temp_df.set_index("file_name")
    temp_df = temp_df.astype(np.float64)
    scaled_df = xai_class.scaler.transform(temp_df)
    scaled_df = np.where(scaled_df > 1, 1, scaled_df)
    temp_df = pd.DataFrame(scaled_df, index=temp_df.index, columns=temp_df.columns)
    temp_df['class'] = _class
    return temp_df

xai_class = XAI_class()
from pathlib import Path
paths = Path("../../Data/").glob("*.csv")
for p in paths:
    if "train" in str(p):
        continue
    temp_df = read_data(p)
    xai_class.target_shap_value(temp_df)