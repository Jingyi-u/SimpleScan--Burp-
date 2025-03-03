import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import java.awt.*;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class CustomLogger implements BurpExtension {

    private MontoyaApi api;
    private ConfigModel configModel;


    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("SimpleScan");
        api.logging().logToOutput("Success\n");
        api.logging().logToOutput("Github: https://github.com/Jingyi-u/SimpleScan--Burp-\n");


        MyTableModel tableModel = new MyTableModel();
        configModel  = new ConfigModel(); // 新增配置模型

        api.userInterface().registerSuiteTab("Simple Scan", constructLoggerTab(tableModel));
        api.http().registerHttpHandler(new MyHttpHandler(api, tableModel,configModel));
    }

    private Component constructLoggerTab(MyTableModel tableModel) {
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        UserInterface userInterface = api.userInterface();


        // 底部的请求和响应编辑器
        HttpRequestEditor requestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
        HttpResponseEditor responseViewer = userInterface.createHttpResponseEditor(READ_ONLY);


        JTable logTable = new JTable(tableModel) {
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                SourceLogEntry sourceLogEntry = tableModel.get(rowIndex);
                requestViewer.setRequest(sourceLogEntry.getHttpRequestResponse().request());
                responseViewer.setResponse(sourceLogEntry.getHttpRequestResponse().response());
                super.changeSelection(rowIndex, columnIndex, toggle, extend);
            }
        };
        JScrollPane logScrollPane = new JScrollPane(logTable);

        // 创建请求和响应的选项卡
        JTabbedPane requestTabs = new JTabbedPane();
        requestTabs.addTab("Request", requestViewer.uiComponent());
        JTabbedPane responseTabs = new JTabbedPane();
        responseTabs.addTab("Response", responseViewer.uiComponent());

        JSplitPane requestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        requestResponseSplitPane.setLeftComponent(requestTabs);
        requestResponseSplitPane.setRightComponent(responseTabs);
        requestResponseSplitPane.setResizeWeight(0.5); // 设置左右比例为 50%

        // 创建右侧的配置面板
        JPanel rightPanel = new JPanel(new GridBagLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder("Config"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        gbc.gridy = 0;

        // 创建开关选项
        JCheckBox bypass403 = new JCheckBox("Bypass 403");
        bypass403.addActionListener(e -> {
            configModel.setBypass403Enabled(bypass403.isSelected());
        });
        rightPanel.add(bypass403, gbc);

        gbc.gridy++;
        JCheckBox fastjson = new JCheckBox("Fastjson");
        fastjson.addActionListener(e -> {
            configModel.setFastjsonEnabled(fastjson.isSelected());
        });
        rightPanel.add(fastjson, gbc);

        gbc.gridy++;
        JCheckBox springboot = new JCheckBox("SpringBoot Scan");
        springboot.addActionListener(e -> {
            configModel.setSpringbootEnabled(springboot.isSelected());
        });
        rightPanel.add(springboot, gbc);

        gbc.gridy++;
        JCheckBox cors = new JCheckBox("CORS");
        cors.addActionListener(e -> {
            configModel.setCorsEnabled(cors.isSelected());
        });
        rightPanel.add(cors, gbc);

        gbc.gridy++;
        JCheckBox sql = new JCheckBox("junior SqlScan");
        sql.addActionListener(e -> {
            configModel.setJuniorSqlEnabled(sql.isSelected());
        });
        rightPanel.add(sql, gbc);

        // 创建左侧的主面板
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(logScrollPane, BorderLayout.NORTH);
        leftPanel.add(requestResponseSplitPane, BorderLayout.CENTER);

        // 主水平分割面板设置
        mainSplitPane.setLeftComponent(leftPanel); // 左侧为主面板
        mainSplitPane.setRightComponent(rightPanel); // 右侧为配置面板
        mainSplitPane.setResizeWeight(0.7); // 设置比例，左侧占 70%

        return mainSplitPane;
    }


}





