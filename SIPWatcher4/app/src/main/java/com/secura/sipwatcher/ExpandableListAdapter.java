package com.secura.sipwatcher;

import java.util.HashMap;
import java.util.List;

import android.content.Context;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseExpandableListAdapter;
import android.widget.TextView;

public class ExpandableListAdapter extends BaseExpandableListAdapter {

    private Context      _context;
    private List<String> _listDataHeader; // header titles

    // child data in format of header title, child title
    private HashMap<String, List<String>> _listDataChild;

    public ExpandableListAdapter(Context                       context,
                                 List<String>                  listDataHeader,
                                 HashMap<String, List<String>> listChildData) {
        this._context        = context;
        this._listDataHeader = listDataHeader;
        this._listDataChild  = listChildData;
    }

    @Override
    public Object getChild(int groupPosition, int childPosititon) {
        return this._listDataChild.get(this._listDataHeader.get(groupPosition)).get(childPosititon);
    }

    @Override
    public long getChildId(int groupPosition, int childPosition) {
        return childPosition;
    }

    @Override
    public View getChildView(int groupPosition,
                             final int childPosition,
                             boolean isLastChild,
                             View convertView,
                             ViewGroup parent) {
        final String childText = (String) getChild(groupPosition, childPosition);

        if (convertView == null) {
            LayoutInflater infalInflater = (LayoutInflater) this._context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = infalInflater.inflate(R.layout.list_item, null);
        }

        TextView txtListChild = (TextView) convertView.findViewById(R.id.lblListItem);

        // Calculate padding
        int i;
        for(i = 0; i < childText.length(); i++){
            if(childText.charAt(i) != ' '){
                break;
            }
        }
        txtListChild.setText(childText.trim());
        txtListChild.setPadding(i*5, 5, 0, 0);


        return convertView;
    }

    @Override
    public int getChildrenCount(int groupPosition) {
        return this._listDataChild.get(this._listDataHeader.get(groupPosition)).size();
    }

    @Override
    public Object getGroup(int groupPosition) {
        return this._listDataHeader.get(groupPosition);
    }

    @Override
    public int getGroupCount() {
        return this._listDataHeader.size();
    }

    @Override
    public long getGroupId(int groupPosition) {
        return groupPosition;
    }

    @Override
    public View getGroupView(int        groupPosition,
                             boolean    isExpanded,
                             View       convertView,
                             ViewGroup  parent) {

        String headerTitle = (String) getGroup(groupPosition);
        if (convertView == null) {
            LayoutInflater infalInflater = (LayoutInflater) this._context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView                  = infalInflater.inflate(R.layout.list_group, null);
        }

        TextView lblListHeader = convertView.findViewById(R.id.lblListHeader);
        lblListHeader.setTypeface(null, Typeface.BOLD);
        lblListHeader.setText(headerTitle);

        // Align text left & right to indicate in- or outbound messages.
        if(headerTitle.contains("↓")){
            lblListHeader.setGravity(Gravity.RIGHT);
        } else if (headerTitle.contains("↑"))  {
            lblListHeader.setGravity(Gravity.LEFT);
        }

        return convertView;
    }


    @Override
    public boolean hasStableIds() {
        return false;
    }

    @Override
    public boolean isChildSelectable(int groupPosition, int childPosition) {
        return true;
    }
}