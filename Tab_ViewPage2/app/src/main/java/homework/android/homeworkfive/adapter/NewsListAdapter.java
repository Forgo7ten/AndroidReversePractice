package homework.android.homeworkfive.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import com.bumptech.glide.Glide;

import java.util.List;

import homework.android.homeworkfive.R;
import homework.android.homeworkfive.entity.News;

public class NewsListAdapter extends BaseAdapter {
    private final int itemLayoutId;
    private final List<News> newsList;
    private final Context mContext;
    private Boolean flag;

    public NewsListAdapter(int itemLayoutId, List<News> newsList, Context mContext) {
        this.itemLayoutId = itemLayoutId;
        this.newsList = newsList;
        this.mContext = mContext;
    }

    @Override
    public int getCount() {
        if (newsList != null) {
            return newsList.size();
        }
        return 0;
    }

    @Override
    public Object getItem(int position) {
        if (newsList != null) {
            return newsList.get(position);
        }
        return null;
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder viewHolder;
        //需要加载子Item的布局，并获取布局中的控件元素，而且设置相应的数据源值
        //1. 获取子布局
        if (null == convertView) {
            //
            convertView = LayoutInflater.from(mContext).inflate(itemLayoutId, null);
            //初始化ViewHolder对象，以方便保存子布局
            viewHolder = new ViewHolder();
            //给ViewHolder的属性赋值
            viewHolder.tvTitle = convertView.findViewById(R.id.item_tv_title);
            viewHolder.tvDate = convertView.findViewById(R.id.item_tv_date);
            viewHolder.img1 = convertView.findViewById(R.id.item_img1);
            viewHolder.img2 = convertView.findViewById(R.id.item_img2);
            viewHolder.img3 = convertView.findViewById(R.id.item_img3);
            //保存子布局
            convertView.setTag(viewHolder);
        } else {
            //获取已经保存的子布局
            viewHolder = (ViewHolder) convertView.getTag();
        }
        //给子布局中的控件设置相应的数据源值
        //得到子Item的数据
        News news = newsList.get(position);
        viewHolder.tvTitle.setText(news.getTitle());
        viewHolder.tvDate.setText(news.getDate());
        flag = false;
        loadImg(viewHolder.img1, news.getThumbnail_pic_s());
        loadImg(viewHolder.img2, news.getThumbnail_pic_s02());
        loadImg(viewHolder.img3, news.getThumbnail_pic_s03());
        return convertView;
    }

    private void loadImg(ImageView imageView, String imgUrl) {
        if (imgUrl != null) {
            Glide.with(mContext)
                    .load(imgUrl)
                    .into(imageView);
            imageView.setVisibility(View.VISIBLE);
            flag = true;
        } else if (flag) {
            imageView.setVisibility(View.INVISIBLE);
        }
    }

    final static class ViewHolder {
        TextView tvTitle;
        TextView tvDate;
        ImageView img1;
        ImageView img2;
        ImageView img3;
    }
}
