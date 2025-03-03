/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */



import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class MyTableModel extends AbstractTableModel
{
    public final List<SourceLogEntry> log;

    public MyTableModel()
    {
        this.log = new ArrayList<>();
    }

    @Override
    public synchronized int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 5;
    }
    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return "ID";
            case 1:
                return "URL";
            case 2:
                return "返回包长度";
            case 3:
                return "状态";
            case 4:
                return "Vulnerability";
            default:
                return "";
        }
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        SourceLogEntry logEntry = log.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return logEntry.getId();
            case 1:
                return logEntry.getHttpService()+ logEntry.getPath();
            case 2:
                return logEntry.getBodyLength();
            case 3:
                return logEntry.getStatus();
            case 4:
                return logEntry.getVulnState();
            default:
                return "";
        }
    }

    public synchronized void add(SourceLogEntry logEntry)
    {
        int index = log.size();
        log.add(logEntry);
        fireTableRowsInserted(index, index);
    }

    public synchronized SourceLogEntry get(int rowIndex) {
        return log.get(rowIndex);
    }
}