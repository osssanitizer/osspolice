from bokeh.io import output_notebook
output_notebook()

from bokeh.io import show, vplot
from bokeh.models import ColumnDataSource, CustomJS
from bokeh.models.layouts import HBox
from bokeh.models.widgets import Button, DataTable, Select, Slider, TableColumn

from bokeh.sampledata.periodic_table import elements

def plot_datatable(df):
    df = df.copy()
    # deal with some atomic mass values of the form '[98]'
    df['atomic mass'] = df['atomic mass'].str.extract('([\d\.]+)').astype(float)
    
    columns = [
        TableColumn(field='atomic number', title='Atomic Number'),
        TableColumn(field='symbol', title='Symbol'),
        TableColumn(field='name', title='Name'),
        TableColumn(field='metal', title='Type'),
        TableColumn(field='atomic mass', title='Atomic Mass')
    ]
    column_names = [tc.field for tc in columns]
    source = ColumnDataSource(df[column_names])
    original_source = ColumnDataSource(df)
    data_table = DataTable(source=source, columns=columns, height=600, editable=False)
    
    widget_callback_code = """
    var filtered_data = filtered_source.get('data');
    var original_data = original_source.get('data');
    
    var element_type = element_type_select.get('value');
    var min_mass = min_mass_slider.get('value');
    
    // now construct the new data object based on the filtered values
    for (var key in original_data) {
        filtered_data[key] = [];
        for (var i = 0; i < original_data[key].length; ++i) {
            if ((element_type === "ALL" || original_data["metal"][i] === element_type) &&
                (original_data['atomic mass'][i] >= min_mass)) {
                filtered_data[key].push(original_data[key][i]);
            }
        }
    }
    target_obj.trigger('change');
    filtered_source.trigger('change');
    """
    
    # define the filter widgets, without callbacks for now
    element_type_list = ['ALL'] + df['metal'].unique().tolist()
    element_type_select = Select(title="Element Type:", value=element_type_list[0], options=element_type_list)
    min_mass_slider = Slider(start=0, end=df['atomic mass'].max(), value=1, step=1, title="minimum atomic mass")
    
    # now define the callback objects now that the filter widgets exist
    arg_dct = dict(
        filtered_source=source,
        original_source=original_source,
        element_type_select=element_type_select,
        min_mass_slider=min_mass_slider,
        target_obj=data_table
    )
    generic_callback = CustomJS(args=arg_dct, code=widget_callback_code)

    # connect the callbacks to the filter widgets
    element_type_select.callback = generic_callback
    min_mass_slider.callback = generic_callback
    
    # create a button to collect the filtered results
    # for now, just send json to new window
    send_button_callback_code = """
    var filtered_data = filtered_source.get('data');
    
    var action_items = [];
    for (var i = 0; i < filtered_data['atomic number'].length; ++i) {
        var item = new Object();
        for (var key in filtered_data) {
            item[key] = filtered_data[key][i]
        }
        action_items.push(item);
    }
    var new_window = window.open("data:text/html," + encodeURIComponent(JSON.stringify(action_items)),
                                 "_blank", "location=yes,height=570,width=520,scrollbars=yes,status=yes");
    new_window.focus();
    """
    send_button_callback = CustomJS(args=dict(filtered_source=source), code=send_button_callback_code)
    send_button = Button(label="Send", type="success", callback=send_button_callback)

    input_widgets = HBox(
        children=[
            HBox(children=[element_type_select, ]),
            HBox(children=[min_mass_slider]),
            HBox(children=[send_button]),
        ]
    )
    p = vplot(input_widgets, data_table)
    show(p)
    

plot_datatable(elements)