import matplotlib.pylab as plt
from matplotlib import pyplot
import numpy as np

def bar_plot_from_dict(dict_data, title, dict_data2=None, lowerlimit=1):
    newdict = {k: v for k, v in dict_data.items() if v > lowerlimit}
    fig = plt.figure()
    ax = fig.add_axes([0,0,1,1])
    lists = sorted(newdict.items()) # sorted by key, return a list of tuples
    x, y = zip(*lists) # unpack a list of pairs into two tuples
	
    ax.bar(x, y)
    if dict_data2 != None:
        y2 = [0] * len (y)
        for i in range(len(x)):
            if x[i] in dict_data2:
                y2[i] = dict_data2[x[i]]
        ax.bar(x, y2, bottom=y)

    plt.title(title)
    plt.show()


def box_plot_from_dict(dict_data, title):
    for k in dict_data:
        dict_data[k].sort()
    
    lists = sorted(dict_data.items()) # sorted by key, return a list of tuples
    x, y = zip(*lists) # unpack a list of pairs into two tuples
    
    newy = list()
    maxval = 0.0

    for i in range(len(y)):
        newy.append(y[i][round(len(y[i])*0.05):round(len(y[i])*0.95)])
        if maxval < max(newy[i]):
            maxval = max(newy[i])
    print(maxval)
    
    fig, ax = plt.subplots()
    ax.set(xlim=(0, 1+len(x)), xticks=np.arange(1, 1+len(x)), ylim=(0, maxval + 0.1), yticks=np.linspace(1, maxval+0.1, 10))

    
    VP = ax.boxplot(newy, labels=x, widths=1, patch_artist=True,
                showmeans=True, showfliers=False,
                medianprops={"color": "white", "linewidth": 0.5},
                boxprops={"facecolor": "C0", "edgecolor": "white",
                          "linewidth": 0.5},
                whiskerprops={"color": "C0", "linewidth": 1.5},
                capprops={"color": "C0", "linewidth": 1.5})

    plt.title(title)
    plt.show()
    
def heatmap(categories, numScale, cumulProbaArray, plotTitle):
    cumulProba = np.array(cumulProbaArray)
    fig, ax = pyplot.subplots()
    im = ax.imshow(cumulProba)

    # Show all ticks and label them with the respective list entries
    ax.set_xticks(np.arange(len(numScale)), labels=numScale)
    ax.set_yticks(np.arange(len(categories)), labels=categories)


    # Rotate the tick labels and set their alignment.
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
         rotation_mode="anchor")

    # Loop over data dimensions and create text annotations.
    for i in range(len(categories)):
        for j in range(len(numScale)):
            if cumulProba[i, j] > 0.5:
                c = "black"
            else:
                c="white"

            text = ax.text(j, i, round(cumulProba[i, j], 3),
                           ha="center", va="center", color=c)

    ax.set_title(plotTitle)
    fig.tight_layout()
    pyplot.show()

def visualise_matrix(file_path, mat_shape):
    np_array = np.loadtxt(file_path, delimiter=',')
    np_array.reshape(mat_shape)
    print(np_array.round(decimals=3))


if __name__ == '__main__':
    print(" A :")
    visualise_matrix("A.csv", (6, 6))
    print("\n\n B:")
    visualise_matrix("B.csv", (6, 18))