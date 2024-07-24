import matplotlib.pyplot as plt
import matplotlib
import numpy as np
import sys
import re
from tqdm import tqdm
import pandas as pd
from shap.plots import colors
from scipy.stats._kde import gaussian_kde
labels = {
    'MAIN_EFFECT': "SHAP main effect value for\n%s",
    'INTERACTION_VALUE': "SHAP interaction value",
    'INTERACTION_EFFECT': "SHAP interaction value for\n%s and %s",
    'VALUE': "SHAP value (impact on model output)",
    'GLOBAL_VALUE': "mean(|SHAP value|) (average impact on model output magnitude)",
    'VALUE_FOR': "SHAP value for\n%s",
    'PLOT_FOR': "SHAP plot for %s",
    'FEATURE': "Feature %s",
    'FEATURE_VALUE': "Feature value",
    'FEATURE_VALUE_LOW': "Low",
    'FEATURE_VALUE_HIGH': "High",
    'JOINT_VALUE': "Joint SHAP value",
    'MODEL_OUTPUT': "Model output value"
}


def sig(x):
    return 1 / (1 + np.exp(-x))

def shorten_text(text, length_limit):
    if len(text) > length_limit:
        return text[:length_limit - 3] + "..."
    else:
        return text


def safe_isinstance(obj, class_path_str):
    """
    Acts as a safe version of isinstance without having to explicitly
    import packages which may not exist in the users environment.

    Checks if obj is an instance of type specified by class_path_str.

    Parameters
    ----------
    obj: Any
        Some object you want to test against
    class_path_str: str or list
        A string or list of strings specifying full class paths
        Example: `sklearn.ensemble.RandomForestRegressor`

    Returns
    --------
    bool: True if isinstance is true and the package exists, False otherwise
    """
    if isinstance(class_path_str, str):
        class_path_strs = [class_path_str]
    elif isinstance(class_path_str, list) or isinstance(class_path_str, tuple):
        class_path_strs = class_path_str
    else:
        class_path_strs = ['']

    # try each module path in order
    for class_path_str in class_path_strs:
        if "." not in class_path_str:
            raise ValueError("class_path_str must be a string or list of strings specifying a full \
                module path to a class. Eg, 'sklearn.ensemble.RandomForestRegressor'")

        # Splits on last occurence of "."
        module_name, class_name = class_path_str.rsplit(".", 1)

        # here we don't check further if the model is not imported, since we shouldn't have
        # an object of that types passed to us if the model the type is from has never been
        # imported. (and we don't want to import lots of new modules for no reason)
        if module_name not in sys.modules:
            continue

        module = sys.modules[module_name]

        # Get class
        _class = getattr(module, class_name, None)

        if _class is None:
            continue

        if isinstance(obj, _class):
            return True

    return False


def format_value(s, format_str):
    """ Strips trailing zeros and uses a unicode minus sign.
    """

    if not issubclass(type(s), str):
        s = format_str % s
    s = re.sub(r'\.?0+$', '', s)
    if s[0] == "-":
        s = u"\u2212" + s[1:]
    return s


def waterfall(shap_values_list: list = None, max_display=10, show=True):
    """ Plots an explantion of a single prediction as a waterfall plot.

    The SHAP value of a feature represents the impact of the evidence provided by that feature on the model's
    output. The waterfall plot is designed to visually display how the SHAP values (evidence) of each feature
    move the model output from our prior expectation under the background data distribution, to the final model
    prediction given the evidence of all the features. Features are sorted by the magnitude of their SHAP values
    with the smallest magnitude features grouped together at the bottom of the plot when the number of features
    in the models exceeds the max_display parameter.

    Parameters
    ----------
    shap_values : Explanation
        A one-dimensional Explanation object that contains the feature values and SHAP values to plot.

    max_display : str
        The maximum number of features to plot.

    show : bool
        Whether matplotlib.pyplot.show() is called before returning. Setting this to False allows the plot
        to be customized further after it has been created.
    """

    # Turn off interactive plot
    if show is False:
        plt.ioff()

    plt.clf()
    x_col = 3
    y_col = 1
    plt.subplots(x_col, y_col, figsize=(8, 18), constrained_layout=True)
    return_df = pd.DataFrame()
    _classs_name = ['target', 'normal', 'malware']
    order = None
    for index, shap_values in enumerate(shap_values_list):
        plt.subplot(x_col, y_col, index + 1)
        base_values = shap_values.base_values
        features = shap_values.display_data if shap_values.display_data is not None else shap_values.data
        feature_names = shap_values.feature_names
        lower_bounds = getattr(shap_values, "lower_bounds", None)
        upper_bounds = getattr(shap_values, "upper_bounds", None)
        values = shap_values.values

        # make sure we only have a single output to explain
        if (type(base_values) == np.ndarray and len(base_values) > 0) or type(base_values) == list:
            raise Exception("waterfall_plot requires a scalar base_values of the model output as the first "
                            "parameter, but you have passed an array as the first parameter! "
                            "Try shap.waterfall_plot(explainer.base_values[0], values[0], X[0]) or "
                            "for multi-output models try "
                            "shap.waterfall_plot(explainer.base_values[0], values[0][0], X[0]).")

        # make sure we only have a single explanation to plot
        if len(values.shape) == 2:
            raise Exception(
                "The waterfall_plot can currently only plot a single explanation but a matrix of explanations was passed!")

        # unwrap pandas series
        if safe_isinstance(features, "pandas.core.series.Series"):
            if feature_names is None:
                feature_names = list(features.index)
            features = features.values

        # fallback feature names
        if feature_names is None:
            feature_names = np.array([labels['FEATURE'] % str(i) for i in range(len(values))])

        # init variables we use for tracking the plot locations
        num_features = min(max_display, len(values))
        row_height = 0.5
        rng = range(num_features - 1, -1, -1)
        if order is None:
            order = np.argsort(-np.abs(values))
        pos_lefts = []
        pos_inds = []
        pos_widths = []
        pos_low = []
        pos_high = []
        neg_lefts = []
        neg_inds = []
        neg_widths = []
        neg_low = []
        neg_high = []
        loc = base_values + values.sum()
        yticklabels = ["" for i in range(num_features + 1)]
        # size the plot based on how many features we are plotting
        # plt.gcf().set_size_inches(8, num_features * row_height + 1.5)
        plt.gcf().set_size_inches(15, num_features * row_height + 3)

        # see how many individual (vs. grouped at the end) features we are plotting
        if num_features == len(values):
            num_individual = num_features
        else:
            num_individual = num_features - 1

        # compute the locations of the individual features and plot the dashed connecting lines

        temp_series = pd.Series()
        for i in range(num_individual):
            sval = values[order[i]]
            loc -= sval
            temp_series[feature_names[order[i]]] = sval

            if sval >= 0:
                pos_inds.append(rng[i])
                pos_widths.append(sval)
                if lower_bounds is not None:
                    pos_low.append(lower_bounds[order[i]])
                    pos_high.append(upper_bounds[order[i]])
                pos_lefts.append(loc)
            else:
                neg_inds.append(rng[i])
                neg_widths.append(sval)
                if lower_bounds is not None:
                    neg_low.append(lower_bounds[order[i]])
                    neg_high.append(upper_bounds[order[i]])
                neg_lefts.append(loc)
            if num_individual != num_features or i + 4 < num_individual:
                plt.plot([loc, loc], [rng[i] - 1 - 0.4, rng[i] + 0.4], color="#bbbbbb", linestyle="--", linewidth=0.5,
                         zorder=-1)
            if features is None:
                yticklabels[rng[i]] = feature_names[order[i]]
            else:
                if np.issubdtype(type(features[order[i]]), np.number):
                    yticklabels[rng[i]] = format_value(float(features[order[i]]), "%0.03f") + " = " + feature_names[
                        order[i]]
                else:
                    yticklabels[rng[i]] = features[order[i]] + " = " + feature_names[order[i]]
        # add a last grouped feature to represent the impact of all the features we didn't show
        if num_features < len(values):
            yticklabels[0] = "%d other features" % (len(values) - num_features + 1)
            remaining_impact = base_values - loc
            if remaining_impact < 0:
                pos_inds.append(0)
                pos_widths.append(-remaining_impact)
                pos_lefts.append(loc + remaining_impact)
                c = colors.red_rgb
            else:
                neg_inds.append(0)
                neg_widths.append(-remaining_impact)
                neg_lefts.append(loc + remaining_impact)
                c = colors.blue_rgb

        points = pos_lefts + list(np.array(pos_lefts) + np.array(pos_widths)) + neg_lefts + \
                 list(np.array(neg_lefts) + np.array(neg_widths))
        dataw = np.max(points) - np.min(points)

        # draw invisible bars just for sizing the axes
        label_padding = np.array([0.1 * dataw if w < 1 else 0 for w in pos_widths])
        plt.barh(pos_inds, np.array(pos_widths) + label_padding + 0.02 * dataw,
                 left=np.array(pos_lefts) - 0.01 * dataw, color=colors.red_rgb, alpha=0)

        label_padding = np.array([-0.1 * dataw if -w < 1 else 0 for w in neg_widths])
        plt.barh(neg_inds, np.array(neg_widths) + label_padding - 0.02 * dataw,
                 left=np.array(neg_lefts) + 0.01 * dataw, color=colors.blue_rgb, alpha=0)
        # define variable we need for plotting the arrows
        head_length = 0.08
        bar_width = 0.8
        xlen = plt.xlim()[1] - plt.xlim()[0]
        fig = plt.gcf()
        ax = plt.gca()
        xticks = ax.get_xticks()
        bbox = ax.get_window_extent().transformed(fig.dpi_scale_trans.inverted())
        width, height = bbox.width, bbox.height
        bbox_to_xscale = xlen / width
        hl_scaled = bbox_to_xscale * head_length
        renderer = fig.canvas.get_renderer()

        # draw the positive arrows
        for i in range(len(pos_inds)):
            dist = pos_widths[i]
            arrow_obj = plt.arrow(
                pos_lefts[i], pos_inds[i], max(dist - hl_scaled, 0.000001), 0,
                head_length=min(dist, hl_scaled),
                color=colors.red_rgb, width=bar_width,
                head_width=bar_width
            )

            if pos_low is not None and i < len(pos_low):
                plt.errorbar(
                    pos_lefts[i] + pos_widths[i], pos_inds[i],
                    xerr=np.array([[pos_widths[i] - pos_low[i]], [pos_high[i] - pos_widths[i]]]),
                    ecolor=colors.light_red_rgb
                )

            txt_obj = plt.text(
                pos_lefts[i] + 0.5 * dist, pos_inds[i], format_value(pos_widths[i], '%+0.02f'),
                horizontalalignment='center', verticalalignment='center', color="white",
                fontsize=12
            )
            text_bbox = txt_obj.get_window_extent(renderer=renderer)
            arrow_bbox = arrow_obj.get_window_extent(renderer=renderer)

            # if the text overflows the arrow then draw it after the arrow
            if text_bbox.width > arrow_bbox.width:
                txt_obj.remove()

                txt_obj = plt.text(
                    pos_lefts[i] + (5 / 72) * bbox_to_xscale + dist, pos_inds[i],
                    format_value(pos_widths[i], '%+0.02f'),
                    horizontalalignment='left', verticalalignment='center', color=colors.red_rgb,
                    fontsize=12
                )

        # draw the negative arrows
        for i in range(len(neg_inds)):
            dist = neg_widths[i]

            arrow_obj = plt.arrow(
                neg_lefts[i], neg_inds[i], -max(-dist - hl_scaled, 0.000001), 0,
                head_length=min(-dist, hl_scaled),
                color=colors.blue_rgb, width=bar_width,
                head_width=bar_width
            )

            if neg_low is not None and i < len(neg_low):
                plt.errorbar(
                    neg_lefts[i] + neg_widths[i], neg_inds[i],
                    xerr=np.array([[neg_widths[i] - neg_low[i]], [neg_high[i] - neg_widths[i]]]),
                    ecolor=colors.light_blue_rgb
                )

            txt_obj = plt.text(
                neg_lefts[i] + 0.5 * dist, neg_inds[i], format_value(neg_widths[i], '%+0.02f'),
                horizontalalignment='center', verticalalignment='center', color="white",
                fontsize=12
            )
            text_bbox = txt_obj.get_window_extent(renderer=renderer)
            arrow_bbox = arrow_obj.get_window_extent(renderer=renderer)

            # if the text overflows the arrow then draw it after the arrow
            if text_bbox.width > arrow_bbox.width:
                txt_obj.remove()

                txt_obj = plt.text(
                    neg_lefts[i] - (5 / 72) * bbox_to_xscale + dist, neg_inds[i],
                    format_value(neg_widths[i], '%+0.02f'),
                    horizontalalignment='right', verticalalignment='center', color=colors.blue_rgb,
                    fontsize=12
                )

        # draw the y-ticks twice, once in gray and then again with just the feature names in black
        # The 1e-8 is so matplotlib 3.3 doesn't try and collapse the ticks
        ytick_pos = list(range(num_features)) + list(np.arange(num_features) + 1e-8)
        plt.yticks(ytick_pos, yticklabels[:-1] + [l.split('=')[-1] for l in yticklabels[:-1]], fontsize=13)

        # put horizontal lines for each feature row
        for i in range(num_features):
            plt.axhline(i, color="#cccccc", lw=0.5, dashes=(1, 5), zorder=-1)

        # mark the prior expected value and the model prediction
        plt.axvline(base_values, 0, 1 / num_features, color="#bbbbbb", linestyle="--", linewidth=0.5, zorder=-1)
        fx = base_values + values.sum()
        fx_sig = sig(fx)
        base_values_sig = sig(base_values)
        plt.axvline(fx, 0, 1, color="#bbbbbb", linestyle="--", linewidth=0.5, zorder=-1)

        # clean up the main axis
        plt.gca().xaxis.set_ticks_position('bottom')
        plt.gca().yaxis.set_ticks_position('none')
        plt.gca().spines['right'].set_visible(False)
        plt.gca().spines['top'].set_visible(False)
        plt.gca().spines['left'].set_visible(False)
        ax.tick_params(labelsize=13)
        # plt.xlabel("\nModel output", fontsize=12)

        # draw the E[f(X)] tick mark
        xmin, xmax = ax.get_xlim()
        ax2 = ax.twiny()
        ax2.set_xlim(xmin, xmax)
        ax2.set_xticks(
            [base_values, base_values + 1e-8])  # The 1e-8 is so matplotlib 3.3 doesn't try and collapse the ticks
        # ax2.set_xticklabels(["\n$E[f(X)]$", "\n$ = " + format_value(base_values, "%0.03f") + "$" + "$ ( " + format_value(base_values_sig, "%0.03f") + "$)"], fontsize=12, ha="left")
        ax2.set_xticklabels(["\n$E[f(X)]$", "\n$ = " + format_value(base_values, "%0.03f") + "$"], fontsize=12,
                            ha="left")
        ax2.spines['right'].set_visible(False)
        ax2.spines['top'].set_visible(False)
        ax2.spines['left'].set_visible(False)

        # draw the f(x) tick mark
        ax3 = ax2.twiny()
        ax3.set_xlim(xmin, xmax)
        # The 1e-8 is so matplotlib 3.3 doesn't try and collapse the ticks
        ax3.set_xticks([base_values + values.sum(), base_values + values.sum() + 1e-8])
        ax3.set_xticklabels(
            ["$f(x)$", "$ = " + format_value(fx, "%0.03f") + "$" + "$ ( " + format_value(fx_sig, "%0.03f") + "$)"],
            fontsize=12, ha="left")
        tick_labels = ax3.xaxis.get_majorticklabels()
        tick_labels[0].set_transform(tick_labels[0].get_transform(
        ) + matplotlib.transforms.ScaledTranslation(-10 / 72., 0, fig.dpi_scale_trans))
        tick_labels[1].set_transform(tick_labels[1].get_transform(
        ) + matplotlib.transforms.ScaledTranslation(12 / 72., 0, fig.dpi_scale_trans))
        tick_labels[1].set_color("#999999")
        ax3.spines['right'].set_visible(False)
        ax3.spines['top'].set_visible(False)
        ax3.spines['left'].set_visible(False)

        # adjust the position of the E[f(X)] = x.xx label
        tick_labels = ax2.xaxis.get_majorticklabels()
        tick_labels[0].set_transform(tick_labels[0].get_transform(
        ) + matplotlib.transforms.ScaledTranslation(-20 / 72., 0, fig.dpi_scale_trans))
        tick_labels[1].set_transform(tick_labels[1].get_transform(
        ) + matplotlib.transforms.ScaledTranslation(22 / 72., -1 / 72., fig.dpi_scale_trans))

        tick_labels[1].set_color("#999999")

        # color the y tick labels that have the feature values as gray
        # (these fall behind the black ones with just the feature name)
        tick_labels = ax.yaxis.get_majorticklabels()
        temp_series['fx'] = fx
        temp_series['fx_value'] = sig(fx)
        temp_series['ex'] = base_values
        return_df[_classs_name[index]] = temp_series
        plt.title(_classs_name[index])
        for i in range(num_features):
            tick_labels[i].set_color("#999999")

    return_df = return_df.T
    if show:
        plt.show()
    else:
        return plt.gcf(), return_df


def summary_plot(shap_values, features=None, feature_names=None, max_display=None, plot_type=None,
               color=None, axis_color="#333333", title=None, alpha=1, show=True, sort=True,
               color_bar=True, plot_size="auto", layered_violin_max_num_bins=20, class_names=None,
               class_inds=None,
               color_bar_label=labels["FEATURE_VALUE"],
               # cmap=colors.red_blue,
               cmap='binary',
               # depreciated
               use_log_scale=False,
               target_data = None,
               output_name:str = "./shap.summary_plot"):
    """Create a SHAP beeswarm plot, colored by feature values when they are provided.

    Parameters
    ----------
    shap_values : numpy.array
        For single output explanations this is a matrix of SHAP values (# samples x # features).
        For multi-output explanations this is a list of such matrices of SHAP values.

    features : numpy.array or pandas.DataFrame or list
        Matrix of feature values (# samples x # features) or a feature_names list as shorthand

    feature_names : list
        Names of the features (length # features)

    max_display : int
        How many top features to include in the plot (default is 20, or 7 for interaction plots)

    plot_type : "dot" (default for single output), "bar" (default for multi-output), "violin",
        or "compact_dot".
        What type of summary plot to produce. Note that "compact_dot" is only used for
        SHAP interaction values.

    plot_size : "auto" (default), float, (float, float), or None
        What size to make the plot. By default the size is auto-scaled based on the number of
        features that are being displayed. Passing a single float will cause each row to be that
        many inches high. Passing a pair of floats will scale the plot by that
        number of inches. If None is passed then the size of the current figure will be left
        unchanged.
    """

    target_shap_value = target_data[0].values[0]
    normal_mean_shap_value = target_data[1].values[0]
    malware_mean_shap_value = target_data[2].values[0]
    return_df = pd.DataFrame()
    _classs_name = ['total', 'normal', 'malware']
    if max_display is None:
        max_display = 20
    feature_order = np.argsort(np.abs(target_shap_value))
    feature_order = feature_order[-min(max_display, len(feature_order)):]

    if feature_names is None:
        feature_names = target_data[0].feature_names

    shap_exp = shap_values
    base_value = shap_exp.base_values
    shap_values = shap_exp.values


    ##여기부터 시작
    # if out_names is None: # TODO: waiting for slicer support of this
    #     out_names = shap_exp.output_names
    if features is None:
        features = shap_exp.data
    plt.clf()

    fig = plt.figure(figsize=(12, 6))
    # fig.set_facecolor('blue')
    # fig.set_facecolor('#e1e59d')
    # fig.set_alpha(0.3)
    ax = fig.add_subplot(1, 1, 1)
    # support passing an explanation object
    # sub plot 존재
    # ax = plt.figure(figsize=(12, 6))
    ax.patch.set_facecolor('#e1e59d')
    ax.patch.set_alpha(0.7)
    #
    multi_class = False
    if isinstance(shap_values, list):
        multi_class = True
        if plot_type is None:
            plot_type = "bar"  # default for multi-output explanations
        assert plot_type == "bar", "Only plot_type = 'bar' is supported for multi-output explanations!"
    else:
        if plot_type is None:
            plot_type = "dot"  # default for single output explanations
        assert len(shap_values.shape) != 1, "Summary plots need a matrix of shap_values, not a vector."

    # default color:
    if color is None:
        if plot_type == 'layered_violin':
            color = "coolwarm"
        elif multi_class:
            color = lambda i: colors.red_blue_circle(i / len(shap_values))
        else:
            color = colors.blue_rgb

    idx2cat = None
    # convert from a DataFrame or other types
    if str(type(features)) == "<class 'pandas.core.frame.DataFrame'>":
        if feature_names is None:
            feature_names = features.columns
        # feature index to category flag
        idx2cat = features.dtypes.astype(str).isin(["object", "category"]).tolist()
        features = features.values
    elif isinstance(features, list):
        if feature_names is None:
            feature_names = features
        features = None
    elif (features is not None) and len(features.shape) == 1 and feature_names is None:
        feature_names = features
        features = None

    num_features = (shap_values[0].shape[1] if multi_class else shap_values.shape[1])

    if features is not None:
        shape_msg = "The shape of the shap_values matrix does not match the shape of the " \
                    "provided data matrix."
        if num_features - 1 == features.shape[1]:
            assert False, shape_msg + " Perhaps the extra column in the shap_values matrix is the " \
                                      "constant offset? Of so just pass shap_values[:,:-1]."
        else:
            assert num_features == features.shape[1], shape_msg

    if feature_names is None:
        feature_names = np.array([labels['FEATURE'] % str(i) for i in range(num_features)])

    if use_log_scale:
        plt.xscale('symlog')

    # plotting SHAP interaction values
    # multi calss 아니니 debuging을 위해 지움
    # if not multi_class and len(shap_values.shape) == 3:
    #     if plot_type == "compact_dot":
    #         new_shap_values = shap_values.reshape(shap_values.shape[0], -1)
    #         new_features = np.tile(features, (1, 1, features.shape[1])).reshape(features.shape[0], -1)
    #
    #         new_feature_names = []
    #         for c1 in feature_names:
    #             for c2 in feature_names:
    #                 if c1 == c2:
    #                     new_feature_names.append(c1)
    #                 else:
    #                     new_feature_names.append(c1 + "* - " + c2)
    #
    #         return summary_plot(
    #             new_shap_values, new_features, new_feature_names,
    #             max_display=max_display, plot_type="dot", color=color, axis_color=axis_color,
    #             title=title, alpha=alpha, show=show, sort=sort,
    #             color_bar=color_bar, plot_size=plot_size, class_names=class_names,
    #             color_bar_label="*" + color_bar_label
    #         )
    #
    #     if max_display is None:
    #         max_display = 7
    #     else:
    #         max_display = min(len(feature_names), max_display)
    #
    #     sort_inds = np.argsort(-np.abs(shap_values.sum(1)).sum(0))
    #
    #     # get plotting limits
    #     delta = 1.0 / (shap_values.shape[1] ** 2)
    #     slow = np.nanpercentile(shap_values, delta)
    #     shigh = np.nanpercentile(shap_values, 100 - delta)
    #     v = max(abs(slow), abs(shigh))
    #     slow = -v
    #     shigh = v
    #
    #     plt.figure(figsize=(1.5 * max_display + 1, 0.8 * max_display + 1))
    #     plt.subplot(1, max_display, 1)
    #     proj_shap_values = shap_values[:, sort_inds[0], sort_inds]
    #     proj_shap_values[:, 1:] *= 2  # because off diag effects are split in half
    #     summary_plot(
    #         proj_shap_values, features[:, sort_inds] if features is not None else None,
    #         feature_names=feature_names[sort_inds],
    #         sort=False, show=False, color_bar=False,
    #         plot_size=None,
    #         max_display=max_display
    #     )
    #     plt.xlim((slow, shigh))
    #     plt.xlabel("")
    #     title_length_limit = 11
    #     plt.title(shorten_text(feature_names[sort_inds[0]], title_length_limit))
    #     for i in range(1, min(len(sort_inds), max_display)):
    #         ind = sort_inds[i]
    #         plt.subplot(1, max_display, i + 1)
    #         proj_shap_values = shap_values[:, ind, sort_inds]
    #         proj_shap_values *= 2
    #         proj_shap_values[:, i] /= 2  # because only off diag effects are split in half
    #         summary_plot(
    #             proj_shap_values, features[:, sort_inds] if features is not None else None,
    #             sort=False,
    #             feature_names=["" for i in range(len(feature_names))],
    #             show=False,
    #             color_bar=False,
    #             plot_size=None,
    #             max_display=max_display
    #         )
    #         plt.xlim((slow, shigh))
    #         plt.xlabel("")
    #         if i == min(len(sort_inds), max_display) // 2:
    #             plt.xlabel(labels['INTERACTION_VALUE'])
    #         plt.title(shorten_text(feature_names[ind], title_length_limit))
    #     plt.tight_layout(pad=0, w_pad=0, h_pad=0.0)
    #     plt.subplots_adjust(hspace=0, wspace=0.1)
    #     if show:
    #         plt.show()
    #     return

    # if sort:
    #     # order features by the sum of their effect magnitudes
    #     if multi_class:
    #         feature_order = np.argsort(np.sum(np.mean(np.abs(shap_values), axis=1), axis=0))
    #     else:
    #         feature_order = np.argsort(np.sum(np.abs(shap_values), axis=0))
    #     feature_order = feature_order[-min(max_display, len(feature_order)):]
    # else:
    #     feature_order = np.flip(np.arange(min(max_display, num_features)), 0)

    row_height = 0.4
    if plot_size == "auto":
        plt.gcf().set_size_inches(8, len(feature_order) * row_height + 1.5)
    elif type(plot_size) in (list, tuple):
        plt.gcf().set_size_inches(plot_size[0], plot_size[1])
    elif plot_size is not None:
        plt.gcf().set_size_inches(8, len(feature_order) * plot_size + 1.5)
    plt.axvline(x=0, color="#999999", zorder=-1)

    if plot_type == "dot":
        for pos, i in enumerate(feature_order):
            plt.axhline(y=pos, color="#cccccc", lw=0.5, dashes=(1, 5), zorder=-1)
            shaps = shap_values[:, i]
            values = None if features is None else features[:, i]
            inds = np.arange(len(shaps))
            np.random.shuffle(inds)
            if values is not None:
                values = values[inds]
            shaps = shaps[inds]
            colored_feature = True
            try:
                if idx2cat is not None and idx2cat[i]:  # check categorical feature
                    colored_feature = False
                else:
                    values = np.array(values, dtype=np.float64)  # make sure this can be numeric
            except:
                colored_feature = False
            N = len(shaps)
            # hspacing = (np.max(shaps) - np.min(shaps)) / 200
            # curr_bin = []
            nbins = 100
            quant = np.round(nbins * (shaps - np.min(shaps)) / (np.max(shaps) - np.min(shaps) + 1e-8))
            inds = np.argsort(quant + np.random.randn(N) * 1e-6)
            layer = 0
            last_bin = -1
            ys = np.zeros(N)
            for ind in inds:
                if quant[ind] != last_bin:
                    layer = 0
                ys[ind] = np.ceil(layer / 2) * ((layer % 2) * 2 - 1)
                layer += 1
                last_bin = quant[ind]
            ys *= 0.9 * (row_height / np.max(ys + 1))

            if features is not None and colored_feature:
                # trim the color range, but prevent the color range from collapsing
                vmin = np.nanpercentile(values, 5)
                vmax = np.nanpercentile(values, 95)
                if vmin == vmax:
                    vmin = np.nanpercentile(values, 1)
                    vmax = np.nanpercentile(values, 99)
                    if vmin == vmax:
                        vmin = np.min(values)
                        vmax = np.max(values)
                if vmin > vmax:  # fixes rare numerical precision issues
                    vmin = vmax

                assert features.shape[0] == len(shaps), "Feature and SHAP matrices must have the same number of rows!"

                # plot the nan values in the interaction feature as grey
                nan_mask = np.isnan(values)
                plt.scatter(shaps[nan_mask], pos + ys[nan_mask], color="#777777", vmin=vmin,
                           vmax=vmax, s=16, alpha=alpha, linewidth=0,
                           zorder=3, rasterized=len(shaps) > 500)

                # plot the non-nan values colored by the trimmed feature value
                cvals = values[np.invert(nan_mask)].astype(np.float64)
                cvals_imp = cvals.copy()
                cvals_imp[np.isnan(cvals)] = (vmin + vmax) / 2.0
                cvals[cvals_imp > vmax] = vmax
                cvals[cvals_imp < vmin] = vmin
                ys_list = pos + ys[np.invert(nan_mask)]
                plt.scatter(shaps[np.invert(nan_mask)], ys_list,
                           cmap=cmap, vmin=vmin, vmax=vmax, s=16,
                           c=cvals, alpha=alpha, linewidth=0,
                           zorder=3, rasterized=len(shaps) > 500)
                vline_min = min(ys_list)
                vline_max = max(ys_list)
                l1 = plt.vlines(target_shap_value[i], vline_min, vline_max, color='#1e1a62', linestyle='solid', linewidth=3, zorder=253)
                l2 = plt.vlines(normal_mean_shap_value[i], vline_min, vline_max, color='blue', linestyle='solid', linewidth=3, zorder=254)
                l3 = plt.vlines(malware_mean_shap_value[i], vline_min, vline_max, color='red', linestyle='solid', linewidth=3, zorder=255)
            else:
                plt.scatter(shaps, pos + ys, s=16, alpha=alpha, linewidth=0, zorder=3,
                           color=color if colored_feature else "#777777", rasterized=len(shaps) > 500)

    elif plot_type == "violin":
        for pos, i in enumerate(feature_order):
            plt.axhline(y=pos, color="#cccccc", lw=0.5, dashes=(1, 5), zorder=-1)

        if features is not None:
            global_low = np.nanpercentile(shap_values[:, :len(feature_names)].flatten(), 1)
            global_high = np.nanpercentile(shap_values[:, :len(feature_names)].flatten(), 99)
            for pos, i in enumerate(feature_order):
                shaps = shap_values[:, i]
                shap_min, shap_max = np.min(shaps), np.max(shaps)
                rng = shap_max - shap_min
                xs = np.linspace(np.min(shaps) - rng * 0.2, np.max(shaps) + rng * 0.2, 100)
                if np.std(shaps) < (global_high - global_low) / 100:
                    ds = gaussian_kde(shaps + np.random.randn(len(shaps)) * (global_high - global_low) / 100)(xs)
                else:
                    ds = gaussian_kde(shaps)(xs)
                ds /= np.max(ds) * 3

                values = features[:, i]
                window_size = max(10, len(values) // 20)
                smooth_values = np.zeros(len(xs) - 1)
                sort_inds = np.argsort(shaps)
                trailing_pos = 0
                leading_pos = 0
                running_sum = 0
                back_fill = 0
                for j in range(len(xs) - 1):

                    while leading_pos < len(shaps) and xs[j] >= shaps[sort_inds[leading_pos]]:
                        running_sum += values[sort_inds[leading_pos]]
                        leading_pos += 1
                        if leading_pos - trailing_pos > 20:
                            running_sum -= values[sort_inds[trailing_pos]]
                            trailing_pos += 1
                    if leading_pos - trailing_pos > 0:
                        smooth_values[j] = running_sum / (leading_pos - trailing_pos)
                        for k in range(back_fill):
                            smooth_values[j - k - 1] = smooth_values[j]
                    else:
                        back_fill += 1

                vmin = np.nanpercentile(values, 5)
                vmax = np.nanpercentile(values, 95)
                if vmin == vmax:
                    vmin = np.nanpercentile(values, 1)
                    vmax = np.nanpercentile(values, 99)
                    if vmin == vmax:
                        vmin = np.min(values)
                        vmax = np.max(values)

                # plot the nan values in the interaction feature as grey
                nan_mask = np.isnan(values)
                plt.scatter(shaps[nan_mask], np.ones(shap_values[nan_mask].shape[0]) * pos,
                           color="#777777", vmin=vmin, vmax=vmax, s=9,
                           alpha=alpha, linewidth=0, zorder=1)
                # plot the non-nan values colored by the trimmed feature value
                cvals = values[np.invert(nan_mask)].astype(np.float64)
                cvals_imp = cvals.copy()
                cvals_imp[np.isnan(cvals)] = (vmin + vmax) / 2.0
                cvals[cvals_imp > vmax] = vmax
                cvals[cvals_imp < vmin] = vmin
                plt.scatter(shaps[np.invert(nan_mask)], np.ones(shap_values[np.invert(nan_mask)].shape[0]) * pos,
                           cmap=cmap, vmin=vmin, vmax=vmax, s=9,
                           c=cvals, alpha=alpha, linewidth=0, zorder=1)
                # smooth_values -= nxp.nanpercentile(smooth_values, 5)
                # smooth_values /= np.nanpercentile(smooth_values, 95)
                smooth_values -= vmin
                if vmax - vmin > 0:
                    smooth_values /= vmax - vmin
                for i in range(len(xs) - 1):
                    if ds[i] > 0.05 or ds[i + 1] > 0.05:
                        plt.fill_between([xs[i], xs[i + 1]], [pos + ds[i], pos + ds[i + 1]],
                                        [pos - ds[i], pos - ds[i + 1]],
                                        color=colors.red_blue_no_bounds(smooth_values[i]),
                                        zorder=2)

        else:
            parts = plt.violinplot(shap_values[:, feature_order], range(len(feature_order)), points=200, vert=False,
                                  widths=0.7,
                                  showmeans=False, showextrema=False, showmedians=False)

            for pc in parts['bodies']:
                pc.set_facecolor(color)
                pc.set_edgecolor('none')
                pc.set_alpha(alpha)

    elif plot_type == "layered_violin":  # courtesy of @kodonnell
        num_x_points = 200
        bins = np.linspace(0, features.shape[0], layered_violin_max_num_bins + 1).round(0).astype(
            'int')  # the indices of the feature data corresponding to each bin
        shap_min, shap_max = np.min(shap_values), np.max(shap_values)
        x_points = np.linspace(shap_min, shap_max, num_x_points)

        # loop through each feature and plot:
        for pos, ind in enumerate(feature_order):
            # decide how to handle: if #unique < layered_violin_max_num_bins then split by unique value, otherwise use bins/percentiles.
            # to keep simpler code, in the case of uniques, we just adjust the bins to align with the unique counts.
            feature = features[:, ind]
            unique, counts = np.unique(feature, return_counts=True)
            if unique.shape[0] <= layered_violin_max_num_bins:
                order = np.argsort(unique)
                thesebins = np.cumsum(counts[order])
                thesebins = np.insert(thesebins, 0, 0)
            else:
                thesebins = bins
            nbins = thesebins.shape[0] - 1
            # order the feature data so we can apply percentiling
            order = np.argsort(feature)
            # x axis is located at y0 = pos, with pos being there for offset
            y0 = np.ones(num_x_points) * pos
            # calculate kdes:
            ys = np.zeros((nbins, num_x_points))
            for i in range(nbins):
                # get shap values in this bin:
                shaps = shap_values[order[thesebins[i]:thesebins[i + 1]], ind]
                # if there's only one element, then we can't
                if shaps.shape[0] == 1:
                    # to ignore it, just set it to the previous y-values (so the area between them will be zero). Not ys is already 0, so there's
                    # nothing to do if i == 0
                    if i > 0:
                        ys[i, :] = ys[i - 1, :]
                    continue
                # save kde of them: note that we add a tiny bit of gaussian noise to avoid singular matrix errors
                ys[i, :] = gaussian_kde(shaps + np.random.normal(loc=0, scale=0.001, size=shaps.shape[0]))(x_points)
                # scale it up so that the 'size' of each y represents the size of the bin. For continuous data this will
                # do nothing, but when we've gone with the unqique option, this will matter - e.g. if 99% are male and 1%
                # female, we want the 1% to appear a lot smaller.
                size = thesebins[i + 1] - thesebins[i]
                bin_size_if_even = features.shape[0] / nbins
                relative_bin_size = size / bin_size_if_even
                ys[i, :] *= relative_bin_size
            # now plot 'em. We don't plot the individual strips, as this can leave whitespace between them.
            # instead, we plot the full kde, then remove outer strip and plot over it, etc., to ensure no
            # whitespace
            ys = np.cumsum(ys, axis=0)
            width = 0.8
            scale = ys.max() * 2 / width  # 2 is here as we plot both sides of x axis
            for i in range(nbins - 1, -1, -1):
                y = ys[i, :] / scale
                c = plt.get_cmap(color)(i / (
                        nbins - 1)) if color in plt.cm.datad else color  # if color is a cmap, use it, otherwise use a color
                plt.fill_between(x_points, pos - y, pos + y, facecolor=c)
        plt.xlim(shap_min, shap_max)

    elif not multi_class and plot_type == "bar":
        feature_inds = feature_order[:max_display]
        y_pos = np.arange(len(feature_inds))
        global_shap_values = np.abs(shap_values).mean(0)
        plt.barh(y_pos, global_shap_values[feature_inds], 0.7, align='center', color=color)
        plt.yticks(y_pos, fontsize=13)
        plt.gca().set_yticklabels([feature_names[i] for i in feature_inds])

    elif multi_class and plot_type == "bar":
        if class_names is None:
            class_names = ["Class " + str(i) for i in range(len(shap_values))]
        feature_inds = feature_order[:max_display]
        y_pos = np.arange(len(feature_inds))
        left_pos = np.zeros(len(feature_inds))

        if class_inds is None:
            class_inds = np.argsort([-np.abs(shap_values[i]).mean() for i in range(len(shap_values))])
        elif class_inds == "original":
            class_inds = range(len(shap_values))
        for i, ind in enumerate(class_inds):
            global_shap_values = np.abs(shap_values[ind]).mean(0)
            plt.barh(
                y_pos, global_shap_values[feature_inds], 0.7, left=left_pos, align='center',
                color=color(i), label=class_names[ind]
            )
            left_pos += global_shap_values[feature_inds]
        plt.yticks(y_pos, fontsize=13)
        plt.gca().set_yticklabels([feature_names[i] for i in feature_inds])
        plt.legend(frameon=False, fontsize=12)

    ## draw the color bar
    # if color_bar and features is not None and plot_type != "bar" and \
    #         (plot_type != "layered_violin" or color in plt.cm.datad):
    #     import matplotlib.cm as cm
    #     m = cm.ScalarMappable(cmap=cmap if plot_type != "layered_violin" else plt.get_cmap(color))
    #     m.set_array([0, 1])
    #     cb = plt.colorbar(m, ticks=[0, 1], aspect=80)
    #     cb.set_ticklabels([labels['FEATURE_VALUE_LOW'], labels['FEATURE_VALUE_HIGH']])
    #     cb.set_label(color_bar_label, size=12, labelpad=0)
    #     cb.ax.tick_params(labelsize=11, length=0)
    #     cb.set_alpha(1)
    #     cb.outline.set_visible(False)


    # #         bbox = cb.ax.get_window_extent().transformed(plt.gcf().dpi_scale_trans.inverted())
    # #         cb.ax.set_aspect((bbox.height - 0.9) * 20)
    # # cb.draw_all()

    plt.gca().xaxis.set_ticks_position('bottom')
    plt.gca().yaxis.set_ticks_position('none')
    plt.gca().spines['right'].set_visible(False)
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['left'].set_visible(False)
    plt.gca().tick_params(color=axis_color, labelcolor=axis_color)
    plt.yticks(range(len(feature_order)), [feature_names[i] for i in feature_order], fontsize=13)
    if plot_type != "bar":
        plt.gca().tick_params('y', length=20, width=0.5, which='major')
    plt.gca().tick_params('x', labelsize=11)
    plt.ylim(-1, len(feature_order))
    if plot_type == "bar":
        plt.xlabel(labels['GLOBAL_VALUE'], fontsize=13)
    else:
        plt.xlabel(labels['VALUE'], fontsize=13)
    plt.title("summary plot")
    plt.tight_layout()

    if show:
        plt.show()
