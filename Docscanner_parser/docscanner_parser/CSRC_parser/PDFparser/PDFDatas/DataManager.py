import pandas as pd


class Datasets:
    def __init__(self, base_dir="PDFparser/", file_name="pdf_parser.csv", target_dir=None, validation_file_name=None):
        self.basic_dir = base_dir
        df_val = None
        try:
            df = pd.read_csv("{}{}".format(self.basic_dir, file_name), index_col=0)
        except FileNotFoundError:
            self.basic_dir = ""
            df = pd.read_csv("{}{}".format(self.basic_dir, file_name), index_col=0)

        if target_dir is None:
            self.target_dir = self.basic_dir
        else:
            self.target_dir = target_dir

        if validation_file_name is None:
            self.validation_file_name = None
        else:
            self.validation_file_name = validation_file_name
            df_val = pd.read_csv("{}{}".format(self.basic_dir, self.validation_file_name), index_col=0)


        df_columns = list(df.columns)
        for index, column in enumerate(df_columns):
            if '#[0-9]([0-9|A-z])' == column:
                df_columns[index] = "ascii_c"
            elif "," in column:
                df_columns[index] = column.replace(",", "")
        df.columns = df_columns

        self.df = df
        if df_val is not None:
            df_val.columns = df_columns
        self.df_val = df_val

