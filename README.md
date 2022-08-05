# HMM_attack_phase_tagging
Repository containing the program of my master thesis

The dataset files used are available here:
https://nesg.ugr.es/nesg-ugr16/march.php#INI

### To run the program

- Training :

´python3 Main.py --action train --dataset traindataset --transition\_matrix A.csv --emission\_matrix B.csv´

- Evaluation :
´python3 Main.py --action eval --dataset evaldataset --transition\_matrix A.csv --emission\_matrix B.csv --output output.txt´

- Test:
´python3 Main.py --action test --dataset testdataset --transition\_matrix A.csv --emission\_matrix B.csv´

