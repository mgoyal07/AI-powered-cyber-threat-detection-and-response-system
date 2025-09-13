# AI-powered-cyber-threat-detection-and-response-system

# How to Run the Project

## 1. Clone the Repository

```
git clone <repository-url>
cd Threat-Detection-in-Cyber-Security-Using-AI-master
```

## 2. Set Up Python Environment

- Ensure you have Python 3.8 or higher installed.
- (Recommended) Create a virtual environment:

```
python -m venv venv
venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On Linux/Mac
```

## 3. Install Dependencies

```
pip install -r requirements.txt
```

## 4. Download the Dataset

- The project uses the CICIDS 2017 dataset.
- Download the dataset from the official source:  
	[CICIDS 2017 Dataset Download Page](https://www.unb.ca/cic/datasets/malmem-2022.html)  
	(Or search for "CICIDS 2017 dataset" if the link changes.)
- Place the relevant CSV files into the `dataset/` directory.  
	(Some preprocessed files may already be present in `dataset/`.)

## 5. Prepare the Dataset (if needed)

- If you need to preprocess or combine data, use the provided Jupyter notebooks in `src/` (e.g., `Preprocessing.ipynb`, `FeatureSelection.ipynb`).
- You can run these notebooks using Jupyter:

```
pip install notebook
jupyter notebook
```

## 6. Run the Application

- To start the main application (e.g., Flask dashboard):

```
cd src
python app.py
```

- The dashboard will be available at `http://127.0.0.1:5000/` by default.

## 7. Running Other Scripts

- For incident handling, run:

```
python incident_handler.py
```

- For machine learning model training or testing, use:

```
python MachineLearningSep.py
```

## 8. Additional Notes

- All output files (logs, processed data) will be saved in the `incidents/` or `src/incidents/` directories.
- For custom datasets, place your CSV files in the `dataset/` folder and update the scripts accordingly.
# Threat Detection in Cyber Security Using AI

## Overview

The "Threat Detection in Cyber Security Using AI" project aims to develop a threat detection system using machine learning algorithms. The project consists of several steps, each of which contributes to the overall goal of enhancing cyber security. Here's an overview of each step:

### Step 1: Data Preprocessing (PreProcessing.ipynb)

- This step involves data preprocessing to prepare the dataset for machine learning.
- The dataset used is the CIC-IDS2017 dataset, which should be stored in the "CSVs" folder located in the same directory as the program.
- You can access the dataset files [here](https://www.unb.ca/cic/datasets/ids-2017.html).

### Step 2: Attack Data Filtering (AttackDivision.ipynb)

- In this step, the program uses the "all_data.csv" file to create attack-specific files.
- These attack files are then saved in the "./attacks/" directory for further analysis.
- The dataset contains a total of 12 attack types, and this step separates them for individual examination.

### Step 3: Feature Selection and Machine Learning (FeatureSelection.ipynb)

- This step focuses on feature selection for the attack files created in Step 2.
- The program identifies the four features with the highest weight for each file.
- These selected features are used as input for machine learning algorithms.

### Step 4: Machine Learning Algorithm Evaluation (MachineLearningSep.ipynb)

- The final step applies seven machine learning algorithms to each attack file multiple times for robust evaluation.
- Results of these operations are displayed on the screen and saved in the file "./attacks/results_1.csv".
- Additionally, box and whisker graphics representing the results are generated.
- Both the graphics and results are saved in the "./attacks/result_graph_1/" folder.
- 
## Dataset Source

You can access the CIC-IDS2017 dataset [here](https://www.unb.ca/cic/datasets/ids-2017.html).

