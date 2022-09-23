def plot_confusion_matrix_(cm,
                          target_names,
                          title='Confusion matrix',
                          detection_thresh=None,
                          cmap=None,
                          normalize=True):
    import matplotlib.pyplot as plt
    import numpy as np
    import itertools

    accuracy = np.trace(cm) / float(np.sum(cm))
    recall = cm[1, 1] / (cm[1, 0] + cm[1, 1])

    if cmap is None:
        cmap = plt.get_cmap('Blues')

    plt.figure(figsize=(7, 7))
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.colorbar()

    if target_names is not None:
        tick_marks = np.arange(len(target_names))
        plt.xticks(tick_marks, target_names, rotation=45, fontsize=14)
        plt.yticks(tick_marks, target_names, fontsize=14)

    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]


    thresh = cm.max() / 1.5 if normalize else cm.max() / 2
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        if normalize:
            plt.text(j, i, "{:0.4f}".format(cm[i, j]),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black", fontsize=20)
        else:
            plt.text(j, i, "{:,}".format(cm[i, j]),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black", fontsize=20)


    print('Detection_thresh: {}, {}, {}'.format(detection_thresh, int(accuracy*100), int(recall*100)))
    plt.tight_layout()
    plt.title(title + ' (Threshold: ' + str(detection_thresh) + ')', fontsize=19)
    plt.ylabel('True label', fontsize=17)
    plt.xlabel('Predicted label\naccuracy={:0.4f}; recall={:0.4f}'.format(accuracy, recall), fontsize=17)
    plt.show()