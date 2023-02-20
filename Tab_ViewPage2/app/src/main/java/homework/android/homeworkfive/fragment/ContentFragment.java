package homework.android.homeworkfive.fragment;


import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.listener.OnLoadMoreListener;
import com.scwang.smartrefresh.layout.listener.OnRefreshListener;

import java.util.ArrayList;
import java.util.List;

import homework.android.homeworkfive.R;
import homework.android.homeworkfive.activity.NewsDetailActivity;
import homework.android.homeworkfive.adapter.NewsListAdapter;
import homework.android.homeworkfive.entity.News;
import homework.android.homeworkfive.entity.Param;
import homework.android.homeworkfive.model.HttpModel;

public class ContentFragment extends Fragment {
    private SmartRefreshLayout refreshLayout;
    private ListView list;
    private Param param;
    private HttpModel httpModel = new HttpModel();
    private NewsListAdapter adapter;
    private List<News> newsList;
    private final Handler handler = new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(@NonNull Message msg) {
            List<News> list = null;
            switch (msg.what) {
                case HttpModel.GET_LIST_CODE:
                    list = (List<News>) msg.obj;
                    if (list.size() > 0) {
                        newsList.clear();
                        newsList.addAll(list);
                        adapter.notifyDataSetChanged();
                        Toast.makeText(getContext(), "加载成功！", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(getContext(), "加载失败！", Toast.LENGTH_SHORT).show();
                    }
                    break;
                case HttpModel.REFRESH_LIST:
                    list = (List<News>) msg.obj;
                    if (list.size() > 0) {
                        newsList.clear();
                        newsList.addAll(list);
                        adapter.notifyDataSetChanged();
                        Toast.makeText(getContext(), "刷新成功！", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(getContext(), "刷新失败！", Toast.LENGTH_SHORT).show();
                    }
                    refreshLayout.finishRefresh();
                    break;
                case HttpModel.LODE_MORE:
                    list = (List<News>) msg.obj;
                    if (list.size() > 0) {
                        newsList.addAll(list);
                        adapter.notifyDataSetChanged();
                        Toast.makeText(getContext(), "加载成功！", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(getContext(), "加载失败！", Toast.LENGTH_SHORT).show();
                    }
                    refreshLayout.finishLoadMore();
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + msg.what);
            }
        }
    };

    public static ContentFragment newInstance(String type) {
        ContentFragment fragment = new ContentFragment();
        Bundle bundle = new Bundle();
        bundle.putString("type", type);
        fragment.setArguments(bundle);
        return fragment;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_content, null);
        initData();
        initViews(view);
        setListeners();
        return view;
    }

    private void setListeners() {
        //下拉刷新监听器
        refreshLayout.setOnRefreshListener(new OnRefreshListener() {
            @Override
            public void onRefresh(@NonNull RefreshLayout refreshLayout) {
                // TODO 下拉刷新
                param.setPage(1);
                httpModel.getNewsList(param, handler, HttpModel.REFRESH_LIST);
            }
        });
        //上拉加载更多监听器
        refreshLayout.setOnLoadMoreListener(new OnLoadMoreListener() {
            @Override
            public void onLoadMore(@NonNull RefreshLayout refreshLayout) {
                // TODO 上拉加载更多逻辑
                httpModel.getNewsList(param.addPage(), handler, HttpModel.LODE_MORE);
            }
        });

        // listView 单击事件
        list.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> adapterView, View view, int i, long l) {
                Intent intent = new Intent();
                intent.setClass(getContext(), NewsDetailActivity.class);
                intent.putExtra("news_url", newsList.get(i).getUrl());
                startActivity(intent);
            }
        });
    }

    private void initData() {
        String type = getArguments().getString("type");
        param = new Param(type);
        newsList = new ArrayList<News>();
        adapter = new NewsListAdapter(R.layout.layout_item, newsList, getContext());
        httpModel.getNewsList(param, handler, HttpModel.GET_LIST_CODE);
    }

    private void initViews(View view) {
        refreshLayout = view.findViewById(R.id.refresh_layout);
        list = view.findViewById(R.id.list);
        list.setAdapter(adapter);
    }
}