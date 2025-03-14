# from app import app 
with open('./config.py', 'r') as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if line.startswith('MODE_5'):
        rate = 0.001
        batch = None
        loss = 'categorical_focal_crossentropy'
        acc = 'accuracy'
        mode = [loss,rate,acc,batch]
        lines[i] = str("MODE_5 ="+ str(mode)+'\n')
with open('./config.py', 'w') as f:
    f.writelines(lines)  