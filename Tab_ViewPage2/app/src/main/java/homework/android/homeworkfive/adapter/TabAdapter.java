package homework.android.homeworkfive.adapter;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Lifecycle;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import java.util.List;

import homework.android.homeworkfive.fragment.ContentFragment;

public class TabAdapter extends FragmentStateAdapter {
    private List<String> tabList;

    public TabAdapter(@NonNull FragmentManager fragmentManager, @NonNull Lifecycle lifecycle, List<String> tabList) {
        super(fragmentManager, lifecycle);
        this.tabList = tabList;
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        return ContentFragment.newInstance(tabList.get(position));
    }

    @Override
    public int getItemCount() {
        return tabList.size();
    }
}
