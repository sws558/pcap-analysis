import sys
import pickle
import pathlib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

pickle_file = str(pathlib.Path(__file__).parent.absolute()) + '/pickles/LogReg_1.pkl'

# Data to be (or not) standardized
# not_standard = ['Label', 'Dst Port', 'Protocol']
# not_standard = ['Label', 'Protocol']
not_standard = ['Label']

# If prob >= LIMIT then it is considered attack
_LIMIT = 0.75


##############################
# #      Extra functions     ##
##############################

def standardize_one(df, standard, not_standard):
    not_std = df[not_standard]  # what we dont want to standardize
    to_std = df[standard]  # what we want to standardize

    std = StandardScaler()

    values = std.fit_transform(to_std.values)

    to_std = pd.DataFrame(values, index=to_std.index, columns=to_std.columns)
    return pd.concat([not_std, to_std], axis=1)

###############################


# df: dataframe as loaded from csv
# df_predict: dataframe suitable for prediction (less columns) and preprocessed
# df_info: dataframe with info data like timestamp, IPs...
# model: model as loaded from pickle
# filename: csv filename
# only_info: name of the headers of df_info
#
# fun preproc_dataset: preproc function. Prepare dataframes and standardize them
# fun predict: makes a prediction and returns a complete df merging df_info and df_predict
class Model:
    '''ML python model'''

    def __init__(self, filename):
        # Loads pickled model
        with open(pickle_file, 'rb') as f:
            self.model = pickle.load(f)

        # Loads CSV
        try:
            self.df = pd.read_csv(filename, sep=",", header=0, index_col=None, low_memory=False)
        except Exception as e:
            print(e)
            print("File not found")
            exit(3)

        self.filename = filename
        return

    def preproc_dataset(self):
        # We only want some columns.
        # This is the dataframe used to predict, which will need standardization
        self.df_predict = self.df[self.model.data_header]
        return

    def predict(self):
        try:
            x_set = self.df_predict.loc[:, self.df_predict.columns != 'Label']

            labeler = np.vectorize(lambda x: 'Attack' if x >= _LIMIT else 'Benign')

            prediction = self.model.predict_proba(x_set)[:, 1]
            self.df['Label'] = labeler(prediction)
            self.df['Prob'] = prediction
        except Exception:
            print("Error in prediction: Maybe empty pcap?")
            exit(4)

        return

    def save_df(self):
        self.df.to_csv(self.filename, index=False)


def main():
    if len(sys.argv) != 2:
        exit(2)

    filename = sys.argv[1]

    model = Model(filename)

    model.preproc_dataset()
    model.predict()
    model.save_df()


if __name__ == '__main__':
    main()
